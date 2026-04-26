use crate::{
    config::Settings,
    errors::AppError,
    mailer::Mailer,
    models::{
        refresh_token::RefreshToken,
        user::{
            LoginRequest, LogoutRequest, MessageResponse, RefreshRequest, RegisterRequest,
            RegisterResponseData, User, UserResponse,
        },
    },
    services::{tenant::TenantSchemaService, token::TokenService},
};
use argon2::{
    Argon2, PasswordHash, PasswordHasher, PasswordVerifier,
    password_hash::{SaltString, rand_core::OsRng},
};
use chrono::{Duration, Utc};
use sqlx::PgPool;
use uuid::Uuid;
use validator::Validate;

#[derive(Clone)]
pub struct AuthService {
    pool: PgPool,
    settings: Settings,
    token_service: TokenService,
    tenant_service: TenantSchemaService,
    mailer: Mailer,
}

impl AuthService {
    pub fn new(
        pool: PgPool,
        settings: Settings,
        token_service: TokenService,
        tenant_service: TenantSchemaService,
        mailer: Mailer,
    ) -> Self {
        Self {
            pool,
            settings,
            token_service,
            tenant_service,
            mailer,
        }
    }

    pub async fn register(
        &self,
        request: RegisterRequest,
    ) -> Result<RegisterResponseData, AppError> {
        request.validate()?;

        self.ensure_email_available(&request.email).await?;
        let user_role_id = self.tenant_service.role_id_by_name("user").await?;
        let tenant_admin_role_id = self.tenant_service.role_id_by_name("tenant_admin").await?;

        let password_hash = self.hash_password(&request.password)?;
        let user = sqlx::query_as::<_, User>(
            r#"
            INSERT INTO users (id, email, password_hash, first_name, last_name, role_id, is_active, is_verified)
            VALUES ($1, $2, $3, $4, $5, $6, TRUE, FALSE)
            RETURNING id, email, password_hash, first_name, last_name, role_id, is_active, is_verified, created_at, updated_at
            "#,
        )
        .bind(Uuid::new_v4())
        .bind(request.email.to_lowercase())
        .bind(password_hash)
        .bind(request.first_name.trim())
        .bind(request.last_name.trim())
        .bind(user_role_id)
        .fetch_one(&self.pool)
        .await?;

        let slug = TenantSchemaService::build_slug(&user.email);
        let tenant_name = format!("{} {} Workspace", user.first_name, user.last_name);
        let tenant = self
            .tenant_service
            .create_tenant_record(user.id, &tenant_name, &slug, tenant_admin_role_id)
            .await?;

        let verification_token = self
            .token_service
            .create_verification_token(user.id, &user.email)?;

        let mailer = self.mailer.clone();
        let email = user.email.clone();
        let first_name = user.first_name.clone();
        tokio::spawn(async move {
            mailer
                .send_email(
                    &email,
                    "Verify your account",
                    &format!(
                        "Welcome {}, your verification token is: {}",
                        first_name, verification_token
                    ),
                )
                .await;
        });

        Ok(RegisterResponseData {
            user: user.into_response(Some(tenant.id)),
            message: "Registration successful. Verification email sent.".to_string(),
        })
    }

    pub async fn login(
        &self,
        request: LoginRequest,
    ) -> Result<crate::models::user::TokenPairResponseData, AppError> {
        request.validate()?;

        let user = self.user_by_email(&request.email).await?;
        if !user.is_active {
            return Err(AppError::user_inactive());
        }

        self.verify_password(&request.password, &user.password_hash)?;
        let tenant_id = self.tenant_service.first_membership_tenant(user.id).await?;
        let token_pair = self.token_service.issue_token_pair(user.id, tenant_id)?;
        self.store_refresh_token(user.id, tenant_id, &token_pair.refresh_token)
            .await?;

        Ok(token_pair)
    }

    pub async fn refresh(
        &self,
        request: RefreshRequest,
    ) -> Result<crate::models::user::TokenPairResponseData, AppError> {
        request.validate()?;

        let claims = self
            .token_service
            .decode_token(&request.refresh_token)
            .map_err(|error| {
                if error.code == "INVALID_TOKEN" || error.code == "TOKEN_EXPIRED" {
                    AppError::invalid_refresh_token()
                } else {
                    error
                }
            })?;

        if claims.token_type != "refresh" {
            return Err(AppError::invalid_refresh_token());
        }

        let user_id =
            Uuid::parse_str(&claims.sub).map_err(|_| AppError::invalid_refresh_token())?;
        let stored = self
            .active_refresh_token(&request.refresh_token)
            .await?
            .ok_or_else(AppError::invalid_refresh_token)?;

        if stored.user_id != user_id || stored.expires_at <= Utc::now() {
            return Err(AppError::invalid_refresh_token());
        }

        let user = self.user_by_id(user_id).await?;
        if !user.is_active {
            return Err(AppError::user_inactive());
        }

        self.revoke_refresh_token_hash(&stored.token_hash).await?;

        let tenant_id = stored
            .tenant_id
            .or(self.tenant_service.first_membership_tenant(user_id).await?);
        let token_pair = self.token_service.issue_token_pair(user_id, tenant_id)?;
        self.store_refresh_token(user_id, tenant_id, &token_pair.refresh_token)
            .await?;

        Ok(token_pair)
    }

    pub async fn logout(&self, request: LogoutRequest) -> Result<MessageResponse, AppError> {
        request.validate()?;
        let token_hash = self.token_service.hash_token(&request.refresh_token);

        sqlx::query(
            r#"
            UPDATE refresh_tokens
            SET revoked_at = NOW()
            WHERE token_hash = $1 AND revoked_at IS NULL
            "#,
        )
        .bind(token_hash)
        .execute(&self.pool)
        .await?;

        Ok(MessageResponse {
            message: "Logout successful.".to_string(),
        })
    }

    pub async fn me(&self, user_id: Uuid) -> Result<UserResponse, AppError> {
        let user = self.user_by_id(user_id).await?;
        let tenant_id = self.tenant_service.first_membership_tenant(user.id).await?;
        Ok(user.into_response(tenant_id))
    }

    pub async fn user_by_id(&self, user_id: Uuid) -> Result<User, AppError> {
        sqlx::query_as::<_, User>(
            r#"
            SELECT id, email, password_hash, first_name, last_name, role_id, is_active, is_verified, created_at, updated_at
            FROM users
            WHERE id = $1
            "#,
        )
        .bind(user_id)
        .fetch_one(&self.pool)
        .await
        .map_err(|error| match error {
            sqlx::Error::RowNotFound => AppError::auth_required(),
            other => AppError::from(other),
        })
    }

    async fn user_by_email(&self, email: &str) -> Result<User, AppError> {
        sqlx::query_as::<_, User>(
            r#"
            SELECT id, email, password_hash, first_name, last_name, role_id, is_active, is_verified, created_at, updated_at
            FROM users
            WHERE email = $1
            "#,
        )
        .bind(email.to_lowercase())
        .fetch_one(&self.pool)
        .await
        .map_err(|error| match error {
            sqlx::Error::RowNotFound => AppError::invalid_credentials(),
            other => AppError::from(other),
        })
    }

    async fn ensure_email_available(&self, email: &str) -> Result<(), AppError> {
        let exists =
            sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)")
                .bind(email.to_lowercase())
                .fetch_one(&self.pool)
                .await?;

        if exists {
            return Err(AppError::email_exists());
        }

        Ok(())
    }

    fn hash_password(&self, password: &str) -> Result<String, AppError> {
        let salt = SaltString::generate(&mut OsRng);
        Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .map(|hash| hash.to_string())
            .map_err(|_| AppError::internal("Failed to hash password."))
    }

    fn verify_password(&self, password: &str, password_hash: &str) -> Result<(), AppError> {
        let parsed_hash =
            PasswordHash::new(password_hash).map_err(|_| AppError::invalid_credentials())?;

        Argon2::default()
            .verify_password(password.as_bytes(), &parsed_hash)
            .map_err(|_| AppError::invalid_credentials())
    }

    async fn store_refresh_token(
        &self,
        user_id: Uuid,
        tenant_id: Option<Uuid>,
        refresh_token: &str,
    ) -> Result<(), AppError> {
        let expires_at = Utc::now() + Duration::days(self.settings.jwt_refresh_expire_days);
        let token_hash = self.token_service.hash_token(refresh_token);

        sqlx::query(
            r#"
            INSERT INTO refresh_tokens (id, user_id, tenant_id, token_hash, expires_at)
            VALUES ($1, $2, $3, $4, $5)
            "#,
        )
        .bind(Uuid::new_v4())
        .bind(user_id)
        .bind(tenant_id)
        .bind(token_hash)
        .bind(expires_at)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn active_refresh_token(
        &self,
        refresh_token: &str,
    ) -> Result<Option<RefreshToken>, AppError> {
        let token_hash = self.token_service.hash_token(refresh_token);

        sqlx::query_as::<_, RefreshToken>(
            r#"
            SELECT id, user_id, tenant_id, token_hash, expires_at, revoked_at, created_at
            FROM refresh_tokens
            WHERE token_hash = $1
              AND revoked_at IS NULL
            "#,
        )
        .bind(token_hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(AppError::from)
    }

    async fn revoke_refresh_token_hash(&self, token_hash: &str) -> Result<(), AppError> {
        sqlx::query(
            r#"
            UPDATE refresh_tokens
            SET revoked_at = NOW()
            WHERE token_hash = $1 AND revoked_at IS NULL
            "#,
        )
        .bind(token_hash)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn verify_email(&self, token: &str) -> Result<MessageResponse, AppError> {
        let claims = self.token_service.decode_token(token)?;
        if claims.token_type != "verification" {
            return Err(AppError::bad_request("Invalid token type."));
        }
        let user_id =
            Uuid::parse_str(&claims.sub).map_err(|_| AppError::bad_request("Invalid token."))?;
        let user = self.user_by_id(user_id).await?;
        if user.is_verified {
            return Err(AppError::bad_request("Email is already verified."));
        }
        sqlx::query("UPDATE users SET is_verified = TRUE, updated_at = NOW() WHERE id = $1")
            .bind(user_id)
            .execute(&self.pool)
            .await?;
        Ok(MessageResponse {
            message: "Email verified successfully.".to_string(),
        })
    }

    pub async fn forgot_password(&self, email: &str) -> Result<MessageResponse, AppError> {
        let user = match self.user_by_email(email).await {
            Ok(u) => u,
            Err(_) => {
                return Ok(MessageResponse {
                    message: "If an account with that email exists, a reset link has been sent."
                        .to_string(),
                });
            }
        };
        let reset_token = self
            .token_service
            .create_verification_token(user.id, &user.email)?;

        let mailer = self.mailer.clone();
        let email = user.email.clone();
        tokio::spawn(async move {
            mailer
                .send_email(
                    &email,
                    "Password Reset",
                    &format!("Your password reset token is: {}", reset_token),
                )
                .await;
        });

        Ok(MessageResponse {
            message: "If an account with that email exists, a reset link has been sent."
                .to_string(),
        })
    }

    pub async fn reset_password(
        &self,
        token: &str,
        new_password: &str,
    ) -> Result<MessageResponse, AppError> {
        let claims = self.token_service.decode_token(token)?;
        if claims.token_type != "verification" {
            return Err(AppError::bad_request("Invalid token type."));
        }
        let user_id =
            Uuid::parse_str(&claims.sub).map_err(|_| AppError::bad_request("Invalid token."))?;
        let _user = self.user_by_id(user_id).await?;
        let password_hash = self.hash_password(new_password)?;
        sqlx::query("UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2")
            .bind(password_hash)
            .bind(user_id)
            .execute(&self.pool)
            .await?;
        Ok(MessageResponse {
            message: "Password reset successfully.".to_string(),
        })
    }
}
