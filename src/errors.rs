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
