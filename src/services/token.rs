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
        let digest = Sha256::digest(token.as_bytes());
        let mut out = String::with_capacity(digest.len() * 2);
        for byte in digest.iter() {
            use std::fmt::Write;
            let _ = write!(out, "{:02x}", byte);
        }
        out
    }

    pub fn create_verification_token(
        &self,
        user_id: Uuid,
        email: &str,
    ) -> Result<String, AppError> {
        let issued_at = Utc::now();
        let expires_at = issued_at + Duration::days(1);
        let claims = Claims {
            sub: user_id.to_string(),
            exp: expires_at.timestamp() as usize,
            iat: issued_at.timestamp() as usize,
            jti: Uuid::new_v4().to_string(),
            token_type: "verification".to_string(),
            tenant_id: None,
            email: Some(email.to_string()),
        };

        encode(
            &Header::new(self.algorithm()?),
            &claims,
            &EncodingKey::from_secret(self.settings.jwt_secret.as_bytes()),
        )
        .map_err(|_| AppError::internal("Failed to issue verification token."))
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

    #[test]
    fn issue_token_pair_returns_bearer_type() {
        let service = TokenService::new(test_settings());
        let pair = service
            .issue_token_pair(Uuid::new_v4(), None)
            .expect("should issue token pair");
        assert_eq!(pair.token_type, "Bearer");
    }

    #[test]
    fn issue_token_pair_expires_in_matches_settings() {
        let service = TokenService::new(test_settings());
        let pair = service
            .issue_token_pair(Uuid::new_v4(), None)
            .expect("should issue token pair");
        assert_eq!(pair.expires_in, 15 * 60);
    }

    #[test]
    fn decode_token_round_trips_user_id() {
        let service = TokenService::new(test_settings());
        let user_id = Uuid::new_v4();
        let pair = service
            .issue_token_pair(user_id, None)
            .expect("should issue token pair");
        let claims = service
            .decode_token(&pair.access_token)
            .expect("should decode access token");
        assert_eq!(claims.sub, user_id.to_string());
        assert_eq!(claims.token_type, "access");
    }

    #[test]
    fn decode_token_round_trips_tenant_id() {
        let service = TokenService::new(test_settings());
        let user_id = Uuid::new_v4();
        let tenant_id = Uuid::new_v4();
        let pair = service
            .issue_token_pair(user_id, Some(tenant_id))
            .expect("should issue token pair");
        let claims = service
            .decode_token(&pair.access_token)
            .expect("should decode access token");
        assert_eq!(claims.tenant_id, Some(tenant_id.to_string()));
    }

    #[test]
    fn decode_token_invalid_returns_error() {
        let service = TokenService::new(test_settings());
        let result = service.decode_token("not.a.valid.token");
        assert!(result.is_err());
    }

    #[test]
    fn hash_token_is_deterministic() {
        let service = TokenService::new(test_settings());
        let h1 = service.hash_token("my-token");
        let h2 = service.hash_token("my-token");
        assert_eq!(h1, h2);
    }

    #[test]
    fn hash_token_different_inputs_produce_different_hashes() {
        let service = TokenService::new(test_settings());
        let h1 = service.hash_token("token-a");
        let h2 = service.hash_token("token-b");
        assert_ne!(h1, h2);
    }

    #[test]
    fn hash_token_output_is_hex_string() {
        let service = TokenService::new(test_settings());
        let hash = service.hash_token("test");
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(hash.len(), 64); // SHA-256 = 32 bytes = 64 hex chars
    }

    #[test]
    fn create_verification_token_decodes_with_correct_type() {
        let service = TokenService::new(test_settings());
        let user_id = Uuid::new_v4();
        let token = service
            .create_verification_token(user_id, "user@example.com")
            .expect("should create verification token");
        let claims = service
            .decode_token(&token)
            .expect("should decode verification token");
        assert_eq!(claims.token_type, "verification");
        assert_eq!(claims.sub, user_id.to_string());
        assert_eq!(claims.email, Some("user@example.com".to_string()));
    }

    #[test]
    fn unsupported_algorithm_returns_error() {
        let mut settings = test_settings();
        settings.jwt_algorithm = "RS256".to_string();
        let service = TokenService::new(settings);
        let result = service.issue_token_pair(Uuid::new_v4(), None);
        assert!(result.is_err());
    }
}
