use crate::{
    middleware::auth::{AuthUser, require_auth},
    models::user::{LoginRequest, LogoutRequest, RefreshRequest, RegisterRequest},
    response::{created, ok},
    state::AppState,
};
use axum::{
    Extension, Json, Router,
    extract::State,
    middleware,
    response::{IntoResponse, Response},
    routing::{get, post},
};

pub fn auth_routes(state: AppState) -> Router<AppState> {
    let protected = Router::<AppState>::new()
        .route("/me", get(me))
        .route_layer(middleware::from_fn_with_state(state.clone(), require_auth));

    Router::<AppState>::new()
        .route("/register", post(register))
        .route("/login", post(login))
        .route("/refresh", post(refresh))
        .route("/logout", post(logout))
        .merge(protected)
}

#[axum::debug_handler(state = AppState)]
async fn register(State(state): State<AppState>, Json(request): Json<RegisterRequest>) -> Response {
    match state.auth_service.register(request).await {
        Ok(response) => created(response).into_response(),
        Err(error) => error.into_response(),
    }
}

async fn login(State(state): State<AppState>, Json(request): Json<LoginRequest>) -> Response {
    match state.auth_service.login(request).await {
        Ok(response) => ok(response).into_response(),
        Err(error) => error.into_response(),
    }
}

async fn refresh(State(state): State<AppState>, Json(request): Json<RefreshRequest>) -> Response {
    match state.auth_service.refresh(request).await {
        Ok(response) => ok(response).into_response(),
        Err(error) => error.into_response(),
    }
}

async fn logout(State(state): State<AppState>, Json(request): Json<LogoutRequest>) -> Response {
    match state.auth_service.logout(request).await {
        Ok(response) => ok(response).into_response(),
        Err(error) => error.into_response(),
    }
}

async fn me(State(state): State<AppState>, Extension(auth_user): Extension<AuthUser>) -> Response {
    match state.auth_service.me(auth_user.user_id).await {
        Ok(response) => ok(response).into_response(),
        Err(error) => error.into_response(),
    }
}
