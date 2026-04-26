use crate::{errors::AppError, state::AppState};
use axum::{
    extract::{Request, State},
    http::HeaderMap,
    middleware::Next,
    response::Response,
};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct AuthUser {
    pub user_id: Uuid,
}

pub async fn require_auth(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Result<Response, AppError> {
    let token = bearer_token(request.headers())?;
    let claims = state.token_service.decode_token(&token)?;

    if claims.token_type != "access" {
        return Err(AppError::invalid_token());
    }

    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| AppError::invalid_token())?;
    let user = state.auth_service.user_by_id(user_id).await?;
    if !user.is_active {
        return Err(AppError::user_inactive());
    }

    request.extensions_mut().insert(AuthUser { user_id });
    Ok(next.run(request).await)
}

pub fn bearer_token(headers: &HeaderMap) -> Result<String, AppError> {
    let authorization = headers
        .get(axum::http::header::AUTHORIZATION)
        .ok_or_else(AppError::auth_required)?;
    let authorization = authorization
        .to_str()
        .map_err(|_| AppError::auth_required())?;

    authorization
        .strip_prefix("Bearer ")
        .map(|value| value.to_string())
        .ok_or_else(AppError::auth_required)
}
