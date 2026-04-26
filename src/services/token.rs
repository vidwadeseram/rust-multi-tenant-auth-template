use crate::{config::Settings, errors::AppError, models::user::TokenPairResponseData};
use chrono::{Duration, Utc};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
    pub iat: usize,
    pub jti: String,
    pub token_type: String,
    pub tenant_id: Option<String>,
    pub email: Option<String>,
}

#[derive(Clone)]
pub struct TokenService {
    settings: Settings,
}

impl TokenService {
    pub fn new(settings: Settings) -> Self {
        Self { settings }
    }

    pub fn issue_token_pair(
        &self,
        user_id: Uuid,
        tenant_id: Option<Uuid>,
    ) -> Result<TokenPairResponseData, AppError> {
        let access_token = self.encode_claims(
            user_id,
            tenant_id,
            "access",
            Duration::minutes(self.settings.jwt_access_expire_minutes),
        )?;
        let refresh_token = self.encode_claims(
            user_id,
            tenant_id,
            "refresh",
            Duration::days(self.settings.jwt_refresh_expire_days),
        )?;

        Ok(TokenPairResponseData {
            access_token,
            refresh_token,
            token_type: "Bearer".to_string(),
            expires_in: self.settings.jwt_access_expire_minutes * 60,
            tenant_id,
        })
    }

    pub fn decode_token(&self, token: &str) -> Result<Claims, AppError> {
        let algorithm = self.algorithm()?;
        let mut validation = Validation::new(algorithm);
        validation.validate_exp = true;

        decode::<Claims>(
            token,
            &DecodingKey::from_secret(self.settings.jwt_secret.as_bytes()),
            &validation,
        )
        .map(|data| data.claims)
        .map_err(|error| match error.kind() {
            jsonwebtoken::errors::ErrorKind::ExpiredSignature => AppError::token_expired(),
            _ => AppError::invalid_token(),
        })
    }

    pub fn hash_token(&self, token: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    fn encode_claims(
        &self,
        user_id: Uuid,
        tenant_id: Option<Uuid>,
        token_type: &str,
        ttl: Duration,
    ) -> Result<String, AppError> {
        let issued_at = Utc::now();
        let expires_at = issued_at + ttl;
        let algorithm = self.algorithm()?;
        let claims = Claims {
            sub: user_id.to_string(),
            exp: expires_at.timestamp() as usize,
            iat: issued_at.timestamp() as usize,
            jti: Uuid::new_v4().to_string(),
            token_type: token_type.to_string(),
            tenant_id: tenant_id.map(|value| value.to_string()),
            email: None,
        };

        encode(
            &Header::new(algorithm),
            &claims,
            &EncodingKey::from_secret(self.settings.jwt_secret.as_bytes()),
        )
        .map_err(|_| AppError::internal("Failed to issue token."))
    }

    fn algorithm(&self) -> Result<Algorithm, AppError> {
        match self.settings.jwt_algorithm.as_str() {
            "HS256" => Ok(Algorithm::HS256),
            _ => Err(AppError::internal("Unsupported JWT algorithm.")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::TokenService;
    use crate::config::Settings;
    use chrono::Utc;
    use std::{thread, time::Duration as StdDuration};
    use uuid::Uuid;

    fn test_settings() -> Settings {
        Settings {
            database_url: "postgres://postgres:postgres@localhost/test".to_string(),
            jwt_secret: "test-secret".to_string(),
            jwt_algorithm: "HS256".to_string(),
            jwt_access_expire_minutes: 15,
            jwt_refresh_expire_days: 7,
            smtp_host: "localhost".to_string(),
            smtp_port: 1025,
            smtp_sender: "no-reply@example.com".to_string(),
            app_port: 8004,
            bind_port_override: Some(8000),
            multi_tenant_mode: "row".to_string(),
        }
    }

    fn wait_for_fresh_second() {
        let current_second = Utc::now().timestamp();
        while Utc::now().timestamp() == current_second {
            thread::sleep(StdDuration::from_millis(5));
        }
    }

    #[test]
    fn issue_token_pair_generates_unique_refresh_tokens_within_same_second() {
        let service = TokenService::new(test_settings());
        let user_id = Uuid::new_v4();
        let tenant_id = Some(Uuid::new_v4());

        wait_for_fresh_second();

        let first = service
            .issue_token_pair(user_id, tenant_id)
            .expect("first token pair should be issued");
        let second = service
            .issue_token_pair(user_id, tenant_id)
            .expect("second token pair should be issued");

        assert_ne!(
            first.refresh_token, second.refresh_token,
            "refresh tokens should remain unique even when issued in the same second"
        );
    }
}
