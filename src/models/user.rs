use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;
use validator::Validate;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    pub password_hash: String,
    pub first_name: String,
    pub last_name: String,
    pub role_id: Uuid,
    pub is_active: bool,
    pub is_verified: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize)]
pub struct UserResponse {
    pub id: Uuid,
    pub email: String,
    pub first_name: String,
    pub last_name: String,
    pub is_active: bool,
    pub is_verified: bool,
    pub tenant_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl User {
    pub fn into_response(self, tenant_id: Option<Uuid>) -> UserResponse {
        UserResponse {
            id: self.id,
            email: self.email,
            first_name: self.first_name,
            last_name: self.last_name,
            is_active: self.is_active,
            is_verified: self.is_verified,
            tenant_id,
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }
}

#[derive(Debug, Deserialize, Validate)]
pub struct RegisterRequest {
    #[validate(email)]
    pub email: String,
    #[validate(length(min = 8, max = 128))]
    pub password: String,
    #[validate(length(min = 1, max = 100))]
    pub first_name: String,
    #[validate(length(min = 1, max = 100))]
    pub last_name: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct LoginRequest {
    #[validate(email)]
    pub email: String,
    #[validate(length(min = 8, max = 128))]
    pub password: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct RefreshRequest {
    #[validate(length(min = 16))]
    pub refresh_token: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct LogoutRequest {
    #[validate(length(min = 16))]
    pub refresh_token: String,
}

#[derive(Debug, Serialize)]
pub struct RegisterResponseData {
    pub user: UserResponse,
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct TokenPairResponseData {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in: i64,
    pub tenant_id: Option<Uuid>,
}

#[derive(Debug, Serialize)]
pub struct MessageResponse {
    pub message: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct VerifyEmailRequest {
    #[validate(length(min = 1))]
    pub token: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct ForgotPasswordRequest {
    #[validate(email)]
    pub email: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct ResetPasswordRequest {
    #[validate(length(min = 1))]
    pub token: String,
    #[validate(length(min = 8, max = 128))]
    pub new_password: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use uuid::Uuid;
    use validator::Validate;

    fn make_user() -> User {
        User {
            id: Uuid::new_v4(),
            email: "test@example.com".to_string(),
            password_hash: "hashed".to_string(),
            first_name: "Alice".to_string(),
            last_name: "Smith".to_string(),
            role_id: Uuid::new_v4(),
            is_active: true,
            is_verified: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn user_into_response_with_tenant_id() {
        let user = make_user();
        let tenant_id = Some(Uuid::new_v4());
        let resp = user.clone().into_response(tenant_id);
        assert_eq!(resp.id, user.id);
        assert_eq!(resp.email, user.email);
        assert_eq!(resp.tenant_id, tenant_id);
        assert!(resp.is_active);
        assert!(resp.is_verified);
    }

    #[test]
    fn user_into_response_without_tenant_id() {
        let user = make_user();
        let resp = user.into_response(None);
        assert!(resp.tenant_id.is_none());
    }

    #[test]
    fn register_request_valid() {
        let req = RegisterRequest {
            email: "user@example.com".to_string(),
            password: "password123".to_string(),
            first_name: "Bob".to_string(),
            last_name: "Jones".to_string(),
        };
        assert!(req.validate().is_ok());
    }

    #[test]
    fn register_request_invalid_email() {
        let req = RegisterRequest {
            email: "not-an-email".to_string(),
            password: "password123".to_string(),
            first_name: "Bob".to_string(),
            last_name: "Jones".to_string(),
        };
        assert!(req.validate().is_err());
    }

    #[test]
    fn register_request_password_too_short() {
        let req = RegisterRequest {
            email: "user@example.com".to_string(),
            password: "short".to_string(),
            first_name: "Bob".to_string(),
            last_name: "Jones".to_string(),
        };
        assert!(req.validate().is_err());
    }

    #[test]
    fn register_request_empty_first_name() {
        let req = RegisterRequest {
            email: "user@example.com".to_string(),
            password: "password123".to_string(),
            first_name: "".to_string(),
            last_name: "Jones".to_string(),
        };
        assert!(req.validate().is_err());
    }

    #[test]
    fn login_request_valid() {
        let req = LoginRequest {
            email: "user@example.com".to_string(),
            password: "password123".to_string(),
        };
        assert!(req.validate().is_ok());
    }

    #[test]
    fn login_request_invalid_email() {
        let req = LoginRequest {
            email: "bad".to_string(),
            password: "password123".to_string(),
        };
        assert!(req.validate().is_err());
    }

    #[test]
    fn forgot_password_request_valid() {
        let req = ForgotPasswordRequest {
            email: "user@example.com".to_string(),
        };
        assert!(req.validate().is_ok());
    }

    #[test]
    fn forgot_password_request_invalid_email() {
        let req = ForgotPasswordRequest {
            email: "notvalid".to_string(),
        };
        assert!(req.validate().is_err());
    }

    #[test]
    fn refresh_request_valid() {
        let req = RefreshRequest {
            refresh_token: "a".repeat(16),
        };
        assert!(req.validate().is_ok());
    }

    #[test]
    fn refresh_request_token_too_short() {
        let req = RefreshRequest {
            refresh_token: "short".to_string(),
        };
        assert!(req.validate().is_err());
    }

    #[test]
    fn user_response_serializes_to_json() {
        let user = make_user();
        let resp = user.into_response(None);
        let json = serde_json::to_string(&resp).expect("should serialize");
        assert!(json.contains("test@example.com"));
        assert!(json.contains("Alice"));
    }

    #[test]
    fn token_pair_response_data_serializes() {
        let data = TokenPairResponseData {
            access_token: "access".to_string(),
            refresh_token: "refresh".to_string(),
            token_type: "Bearer".to_string(),
            expires_in: 900,
            tenant_id: None,
        };
        let json = serde_json::to_string(&data).expect("should serialize");
        assert!(json.contains("Bearer"));
        assert!(json.contains("access"));
    }

    #[test]
    fn message_response_serializes() {
        let msg = MessageResponse {
            message: "done".to_string(),
        };
        let json = serde_json::to_string(&msg).expect("should serialize");
        assert!(json.contains("done"));
    }
}
