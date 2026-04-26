use axum::{Json, http::StatusCode, response::IntoResponse};
use serde::Serialize;

#[derive(Serialize)]
pub struct DataResponse<T> {
    pub data: T,
}

pub fn ok<T>(data: T) -> impl IntoResponse
where
    T: Serialize,
{
    (StatusCode::OK, Json(DataResponse { data }))
}

pub fn created<T>(data: T) -> impl IntoResponse
where
    T: Serialize,
{
    (StatusCode::CREATED, Json(DataResponse { data }))
}
