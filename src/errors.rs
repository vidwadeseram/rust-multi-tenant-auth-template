use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StartupError {
    #[error("configuration error: {0}")]
    Config(String),
    #[error("environment file error: {0}")]
    EnvFile(#[source] dotenvy::Error),
    #[error("database error: {0}")]
    Database(#[source] sqlx::Error),
}

#[derive(Debug, Clone)]
pub struct AppError {
    pub code: &'static str,
    pub message: String,
    pub status: StatusCode,
}

#[derive(Serialize)]
struct ErrorEnvelope {
    error: ErrorBody,
}

#[derive(Serialize)]
struct ErrorBody {
    code: String,
    message: String,
}

impl AppError {
    pub fn new(code: &'static str, message: impl Into<String>, status: StatusCode) -> Self {
        Self {
            code,
            message: message.into(),
            status,
        }
    }

    pub fn validation(message: impl Into<String>) -> Self {
        Self::new(
            "VALIDATION_ERROR",
            message,
            StatusCode::UNPROCESSABLE_ENTITY,
        )
    }

    pub fn auth_required() -> Self {
        Self::new(
            "AUTHENTICATION_REQUIRED",
            "Authentication required.",
            StatusCode::UNAUTHORIZED,
        )
    }

    pub fn invalid_token() -> Self {
        Self::new("INVALID_TOKEN", "Invalid token.", StatusCode::UNAUTHORIZED)
    }

    pub fn token_expired() -> Self {
        Self::new(
            "TOKEN_EXPIRED",
            "Token has expired.",
            StatusCode::UNAUTHORIZED,
        )
    }

    pub fn invalid_refresh_token() -> Self {
        Self::new(
            "INVALID_REFRESH_TOKEN",
            "Invalid refresh token.",
            StatusCode::UNAUTHORIZED,
        )
    }

    pub fn invalid_credentials() -> Self {
        Self::new(
            "INVALID_CREDENTIALS",
            "Invalid email or password.",
            StatusCode::UNAUTHORIZED,
        )
    }

    pub fn email_exists() -> Self {
        Self::new(
            "EMAIL_ALREADY_EXISTS",
            "Email already exists.",
            StatusCode::CONFLICT,
        )
    }

    pub fn user_inactive() -> Self {
        Self::new("USER_INACTIVE", "User is inactive.", StatusCode::FORBIDDEN)
    }

    pub fn tenant_access_denied() -> Self {
        Self::new(
            "TENANT_ACCESS_DENIED",
            "Tenant access denied.",
            StatusCode::FORBIDDEN,
        )
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(
            "INTERNAL_SERVER_ERROR",
            message,
            StatusCode::INTERNAL_SERVER_ERROR,
        )
    }

    pub fn forbidden(message: &str) -> Self {
        Self::new("FORBIDDEN", message, StatusCode::FORBIDDEN)
    }

    pub fn not_found(message: &str) -> Self {
        Self::new("NOT_FOUND", message, StatusCode::NOT_FOUND)
    }

    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new("BAD_REQUEST", message, StatusCode::BAD_REQUEST)
    }

    pub fn conflict(message: impl Into<String>) -> Self {
        Self::new("CONFLICT", message, StatusCode::CONFLICT)
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let body = ErrorEnvelope {
            error: ErrorBody {
                code: self.code.to_string(),
                message: self.message,
            },
        };

        (self.status, Json(body)).into_response()
    }
}

impl From<sqlx::Error> for AppError {
    fn from(error: sqlx::Error) -> Self {
        if let sqlx::Error::RowNotFound = error {
            return Self::invalid_credentials();
        }

        tracing::error!(error = %error, "database error");
        Self::internal("An unexpected error occurred.")
    }
}

impl From<validator::ValidationErrors> for AppError {
    fn from(error: validator::ValidationErrors) -> Self {
        Self::validation(error.to_string())
    }
}

impl From<sqlx::migrate::MigrateError> for AppError {
    fn from(error: sqlx::migrate::MigrateError) -> Self {
        tracing::error!(error = %error, "migration error");
        Self::internal("An unexpected error occurred.")
    }
}

#[cfg(test)]
mod tests {
    use super::AppError;
    use axum::http::StatusCode;
    use axum::response::IntoResponse;

    #[test]
    fn auth_required_returns_401() {
        let err = AppError::auth_required();
        assert_eq!(err.status, StatusCode::UNAUTHORIZED);
        assert_eq!(err.code, "AUTHENTICATION_REQUIRED");
    }

    #[test]
    fn invalid_token_returns_401() {
        let err = AppError::invalid_token();
        assert_eq!(err.status, StatusCode::UNAUTHORIZED);
        assert_eq!(err.code, "INVALID_TOKEN");
    }

    #[test]
    fn token_expired_returns_401() {
        let err = AppError::token_expired();
        assert_eq!(err.status, StatusCode::UNAUTHORIZED);
        assert_eq!(err.code, "TOKEN_EXPIRED");
    }

    #[test]
    fn forbidden_returns_403() {
        let err = AppError::forbidden("no access");
        assert_eq!(err.status, StatusCode::FORBIDDEN);
        assert_eq!(err.code, "FORBIDDEN");
        assert_eq!(err.message, "no access");
    }

    #[test]
    fn user_inactive_returns_403() {
        let err = AppError::user_inactive();
        assert_eq!(err.status, StatusCode::FORBIDDEN);
        assert_eq!(err.code, "USER_INACTIVE");
    }

    #[test]
    fn tenant_access_denied_returns_403() {
        let err = AppError::tenant_access_denied();
        assert_eq!(err.status, StatusCode::FORBIDDEN);
        assert_eq!(err.code, "TENANT_ACCESS_DENIED");
    }

    #[test]
    fn not_found_returns_404() {
        let err = AppError::not_found("resource missing");
        assert_eq!(err.status, StatusCode::NOT_FOUND);
        assert_eq!(err.code, "NOT_FOUND");
        assert_eq!(err.message, "resource missing");
    }

    #[test]
    fn internal_returns_500() {
        let err = AppError::internal("something broke");
        assert_eq!(err.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(err.code, "INTERNAL_SERVER_ERROR");
        assert_eq!(err.message, "something broke");
    }

    #[test]
    fn validation_returns_422() {
        let err = AppError::validation("bad input");
        assert_eq!(err.status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(err.code, "VALIDATION_ERROR");
    }

    #[test]
    fn bad_request_returns_400() {
        let err = AppError::bad_request("malformed");
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert_eq!(err.code, "BAD_REQUEST");
    }

    #[test]
    fn conflict_returns_409() {
        let err = AppError::conflict("duplicate");
        assert_eq!(err.status, StatusCode::CONFLICT);
        assert_eq!(err.code, "CONFLICT");
    }

    #[test]
    fn email_exists_returns_409() {
        let err = AppError::email_exists();
        assert_eq!(err.status, StatusCode::CONFLICT);
        assert_eq!(err.code, "EMAIL_ALREADY_EXISTS");
    }

    #[test]
    fn into_response_sets_correct_status_code() {
        let err = AppError::not_found("gone");
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn into_response_internal_sets_500() {
        let err = AppError::internal("oops");
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn into_response_forbidden_sets_403() {
        let err = AppError::forbidden("denied");
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn sqlx_row_not_found_maps_to_invalid_credentials() {
        let err = AppError::from(sqlx::Error::RowNotFound);
        assert_eq!(err.status, StatusCode::UNAUTHORIZED);
        assert_eq!(err.code, "INVALID_CREDENTIALS");
    }

    #[test]
    fn new_constructs_with_correct_fields() {
        let err = AppError::new("MY_CODE", "my message", StatusCode::IM_A_TEAPOT);
        assert_eq!(err.code, "MY_CODE");
        assert_eq!(err.message, "my message");
        assert_eq!(err.status, StatusCode::IM_A_TEAPOT);
    }
}
