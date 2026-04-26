use axum::{
    Extension,
    extract::{Path, State},
    routing::{get, patch, post},
    Json, Router,
    response::{IntoResponse, Response},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::{
    errors::AppError,
    middleware::auth::AuthUser,
    models::{
        permission::Permission,
        role::Role,
        user::User,
        user_role::UserRole as UserRoleModel,
    },
    response::ok,
    state::AppState,
};

pub fn admin_routes() -> Router<AppState> {
    Router::new()
        .route("/roles", get(list_roles))
        .route("/permissions", get(list_permissions))
        .route("/roles/{role_id}/permissions", get(get_role_permissions))
        .route("/roles/permissions", post(assign_permission_to_role))
        .route("/users", get(list_users))
        .route("/users/{user_id}", get(get_user))
        .route("/users/{user_id}/patch", patch(update_user))
        .route("/users/{user_id}/permissions", get(get_user_permissions))
        .route("/users/roles", post(assign_role_to_user))
}

async fn require_perm(pool: &PgPool, user_id: Uuid, perm: &str) -> Result<(), AppError> {
    let has = Permission::user_has_permission(pool, user_id, perm)
        .await
        .map_err(|_| AppError::internal("Permission check failed."))?;
    if !has {
        return Err(AppError::forbidden(&format!("Permission '{}' is required.", perm)));
    }
    Ok(())
}

#[derive(Serialize)]
struct RoleOut { id: Uuid, name: String, description: String, created_at: DateTime<Utc> }

#[derive(Serialize)]
struct PermOut { id: Uuid, name: String, description: String, created_at: DateTime<Utc> }

#[derive(Serialize)]
struct UserOut { id: Uuid, email: String, first_name: String, last_name: String, is_active: bool, is_verified: bool, created_at: DateTime<Utc>, updated_at: DateTime<Utc> }

fn user_to_out(u: &User) -> UserOut {
    UserOut { id: u.id, email: u.email.clone(), first_name: u.first_name.clone(), last_name: u.last_name.clone(), is_active: u.is_active, is_verified: u.is_verified, created_at: u.created_at, updated_at: u.updated_at }
}

async fn list_roles(State(state): State<AppState>, Extension(auth): Extension<AuthUser>) -> Response {
    match require_perm(&state.pool, auth.user_id, "roles.manage").await {
        Err(e) => e.into_response(),
        Ok(()) => {
            match Role::all(&state.pool).await {
                Ok(roles) => ok(roles.into_iter().map(|r| RoleOut { id: r.id, name: r.name, description: r.description, created_at: r.created_at }).collect::<Vec<_>>()).into_response(),
                Err(e) => AppError::from(e).into_response(),
            }
        }
    }
}

async fn list_permissions(State(state): State<AppState>, Extension(auth): Extension<AuthUser>) -> Response {
    match require_perm(&state.pool, auth.user_id, "roles.manage").await {
        Err(e) => e.into_response(),
        Ok(()) => {
            match Permission::all(&state.pool).await {
                Ok(perms) => ok(perms.into_iter().map(|p| PermOut { id: p.id, name: p.name, description: p.description, created_at: p.created_at }).collect::<Vec<_>>()).into_response(),
                Err(e) => AppError::from(e).into_response(),
            }
        }
    }
}

async fn get_role_permissions(State(state): State<AppState>, Extension(auth): Extension<AuthUser>, Path(role_id): Path<Uuid>) -> Response {
    match require_perm(&state.pool, auth.user_id, "roles.manage").await {
        Err(e) => e.into_response(),
        Ok(()) => {
            match Permission::find_by_role_id(&state.pool, role_id).await {
                Ok(perms) => ok(perms.into_iter().map(|p| PermOut { id: p.id, name: p.name, description: p.description, created_at: p.created_at }).collect::<Vec<_>>()).into_response(),
                Err(e) => AppError::from(e).into_response(),
            }
        }
    }
}

async fn assign_permission_to_role(State(state): State<AppState>, Extension(auth): Extension<AuthUser>, Json(payload): Json<RolePermReq>) -> Response {
    match require_perm(&state.pool, auth.user_id, "roles.manage").await {
        Err(e) => e.into_response(),
        Ok(()) => {
            match Permission::assign_to_role(&state.pool, payload.role_id, payload.permission_id).await {
                Ok(()) => ok(serde_json::json!({"message": "Permission assigned to role."})).into_response(),
                Err(e) => AppError::from(e).into_response(),
            }
        }
    }
}

async fn list_users(State(state): State<AppState>, Extension(auth): Extension<AuthUser>) -> Response {
    match require_perm(&state.pool, auth.user_id, "users.read").await {
        Err(e) => e.into_response(),
        Ok(()) => {
            match sqlx::query_as::<_, User>("SELECT id, email, password_hash, first_name, last_name, role_id, is_active, is_verified, created_at, updated_at FROM users ORDER BY created_at DESC").fetch_all(&state.pool).await {
                Ok(users) => ok(users.iter().map(user_to_out).collect::<Vec<_>>()).into_response(),
                Err(e) => AppError::from(e).into_response(),
            }
        }
    }
}

async fn get_user(State(state): State<AppState>, Extension(auth): Extension<AuthUser>, Path(user_id): Path<Uuid>) -> Response {
    match require_perm(&state.pool, auth.user_id, "users.read").await {
        Err(e) => e.into_response(),
        Ok(()) => {
            match sqlx::query_as::<_, User>("SELECT id, email, password_hash, first_name, last_name, role_id, is_active, is_verified, created_at, updated_at FROM users WHERE id = $1").bind(user_id).fetch_optional(&state.pool).await {
                Ok(Some(user)) => ok(user_to_out(&user)).into_response(),
                Ok(None) => AppError::not_found("User not found.").into_response(),
                Err(e) => AppError::from(e).into_response(),
            }
        }
    }
}

async fn update_user(State(state): State<AppState>, Extension(auth): Extension<AuthUser>, Path(user_id): Path<Uuid>, Json(payload): Json<UserUpdateReq>) -> Response {
    match require_perm(&state.pool, auth.user_id, "users.write").await {
        Err(e) => e.into_response(),
        Ok(()) => {
            if let Some(ref v) = payload.first_name { let _ = sqlx::query("UPDATE users SET first_name=$1, updated_at=NOW() WHERE id=$2").bind(v).bind(user_id).execute(&state.pool).await; }
            if let Some(ref v) = payload.last_name { let _ = sqlx::query("UPDATE users SET last_name=$1, updated_at=NOW() WHERE id=$2").bind(v).bind(user_id).execute(&state.pool).await; }
            if let Some(v) = payload.is_active { let _ = sqlx::query("UPDATE users SET is_active=$1, updated_at=NOW() WHERE id=$2").bind(v).bind(user_id).execute(&state.pool).await; }
            match sqlx::query_as::<_, User>("SELECT id, email, password_hash, first_name, last_name, role_id, is_active, is_verified, created_at, updated_at FROM users WHERE id=$1").bind(user_id).fetch_one(&state.pool).await {
                Ok(user) => ok(user_to_out(&user)).into_response(),
                Err(e) => AppError::from(e).into_response(),
            }
        }
    }
}

async fn get_user_permissions(State(state): State<AppState>, Extension(auth): Extension<AuthUser>, Path(target_id): Path<Uuid>) -> Response {
    match require_perm(&state.pool, auth.user_id, "users.read").await {
        Err(e) => e.into_response(),
        Ok(()) => {
            match Permission::find_by_user_id(&state.pool, target_id).await {
                Ok(perms) => ok(perms.into_iter().map(|p| PermOut { id: p.id, name: p.name, description: p.description, created_at: p.created_at }).collect::<Vec<_>>()).into_response(),
                Err(e) => AppError::from(e).into_response(),
            }
        }
    }
}

async fn assign_role_to_user(State(state): State<AppState>, Extension(auth): Extension<AuthUser>, Json(payload): Json<UserRoleReq>) -> Response {
    match require_perm(&state.pool, auth.user_id, "roles.manage").await {
        Err(e) => e.into_response(),
        Ok(()) => {
            match UserRoleModel::assign(&state.pool, payload.user_id, payload.role_id).await {
                Ok(()) => ok(serde_json::json!({"message": "Role assigned to user."})).into_response(),
                Err(e) => AppError::from(e).into_response(),
            }
        }
    }
}

#[derive(Deserialize)]
struct RolePermReq { role_id: Uuid, permission_id: Uuid }

#[derive(Deserialize)]
struct UserRoleReq { user_id: Uuid, role_id: Uuid }

#[derive(Deserialize)]
struct UserUpdateReq { first_name: Option<String>, last_name: Option<String>, is_active: Option<bool> }
