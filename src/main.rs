mod config;
mod errors;
mod middleware;
mod models;
mod response;
mod routes;
mod services;
mod state;

use axum::{Router, middleware::from_fn_with_state, routing::get};
use config::Settings;
use middleware::{auth::require_auth, tenant::resolve_tenant_context};
use routes::{admin, auth::auth_routes, health::health_routes, tenant};
use services::tenant::{BASE_MIGRATOR, TenantSchemaService};
use state::AppState;
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tower_http::trace::TraceLayer;
use tracing::info;

async fn openapi_spec() -> impl axum::response::IntoResponse {
    (
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        include_str!("../static/openapi.json"),
    )
}

async fn swagger_ui() -> impl axum::response::IntoResponse {
    axum::response::Html(std::include_str!("../static/swagger.html"))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let settings = Settings::load()?;
    settings.init_tracing();

    let pool = settings.database_pool().await?;
    BASE_MIGRATOR.run(&pool).await?;

    let tenant_schema_service = TenantSchemaService::new(pool.clone());
    let state = AppState::new(pool, settings.clone(), tenant_schema_service);

    let app = Router::<AppState>::new()
        .route("/openapi.json", get(openapi_spec))
        .route("/docs", get(swagger_ui))
        .merge(health_routes())
        .nest("/api/v1/auth", auth_routes(state.clone()))
        .nest(
            "/api/v1/admin",
            admin::admin_routes().layer(from_fn_with_state(state.clone(), require_auth)),
        )
        .nest(
            "/api/v1/tenants",
            tenant::tenant_routes().layer(from_fn_with_state(state.clone(), require_auth)),
        )
        .layer(from_fn_with_state(state.clone(), resolve_tenant_context))
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let bind_port = settings.bind_port();
    let addr = SocketAddr::from(([0, 0, 0, 0], bind_port));
    let listener = TcpListener::bind(addr).await?;
    info!(
        port = bind_port,
        mode = %settings.multi_tenant_mode,
        smtp_host = %settings.smtp_host,
        smtp_port = settings.smtp_port,
        smtp_sender = %settings.smtp_sender,
        "server listening"
    );
    axum::serve(listener, app).await?;

    Ok(())
}
