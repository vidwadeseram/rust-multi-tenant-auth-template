use crate::state::AppState;
use axum::{Json, Router, routing::get};
use serde::Serialize;

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse { status: "ok" })
}

pub fn health_routes() -> Router<AppState> {
    Router::<AppState>::new().route("/health", get(health))
}

#[cfg(test)]
mod tests {
    use super::health;
    use axum::response::IntoResponse;

    #[tokio::test]
    async fn health_handler_returns_ok_status() {
        let response = health().await.into_response();
        assert_eq!(response.status(), axum::http::StatusCode::OK);
    }

    #[tokio::test]
    async fn health_handler_body_contains_ok() {
        use axum::body::to_bytes;
        let response = health().await.into_response();
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body should be readable");
        let json: serde_json::Value =
            serde_json::from_slice(&body).expect("body should be valid JSON");
        assert_eq!(json["status"], "ok");
    }
}
