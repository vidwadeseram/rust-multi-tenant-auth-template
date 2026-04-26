use crate::{errors::AppError, middleware::auth::bearer_token, state::AppState};
use axum::{
    extract::{Request, State},
    middleware::Next,
    response::Response,
};
use uuid::Uuid;

pub async fn resolve_tenant_context(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Result<Response, AppError> {
    let tenant_id = request
        .headers()
        .get("X-Tenant-ID")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| Uuid::parse_str(value).ok())
        .or_else(|| {
            bearer_token(request.headers())
                .ok()
                .and_then(|token| state.token_service.decode_token(&token).ok())
                .and_then(|claims| claims.tenant_id)
                .and_then(|value| Uuid::parse_str(&value).ok())
        });

    if let Some(tenant_id) = tenant_id {
        let user_id = bearer_token(request.headers())
            .ok()
            .and_then(|token| state.token_service.decode_token(&token).ok())
            .and_then(|claims| Uuid::parse_str(&claims.sub).ok());

        if let Some(context) = state
            .tenant_schema_service
            .resolve_context(tenant_id, user_id)
            .await?
        {
            request.extensions_mut().insert(context);
        }
    }

    Ok(next.run(request).await)
}
