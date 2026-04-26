use axum::{
    Extension, Json, Router,
    extract::{Path, State},
    response::{IntoResponse, Response},
    routing::{get, patch, post},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::{
    errors::AppError,
    middleware::auth::AuthUser,
    models::{
        permission::Permission, role::Role, user::User, user_role::UserRole as UserRoleModel,
    },
    response::ok,
    services::tenant::TenantContext,
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

async fn require_any_perm(
    pool: &PgPool,
    user_id: Uuid,
    tenant_id: Option<Uuid>,
    permissions: &[&str],
) -> Result<(), AppError> {
    for permission in permissions {
        if Permission::user_has_permission(pool, user_id, permission, tenant_id)
            .await
            .map_err(|_| AppError::internal("Permission check failed."))?
        {
            return Ok(());
        }
    }

    let required = permissions.join(" or ");
    Err(AppError::forbidden(&format!(
        "Permission '{}' is required.",
        required
    )))
}

fn tenant_scope(context: &Option<Extension<TenantContext>>) -> Option<Uuid> {
    context.as_ref().map(|Extension(context)| context.tenant_id)
}

fn tenant_permissions(
    tenant_id: Option<Uuid>,
    global_permission: &'static str,
    tenant_permission: &'static str,
) -> Vec<&'static str> {
    if tenant_id.is_some() {
        vec![global_permission, tenant_permission]
    } else {
        vec![global_permission]
    }
}

async fn load_role(pool: &PgPool, role_id: Uuid) -> Result<Role, AppError> {
    Role::find_by_id(pool, role_id)
        .await?
        .ok_or_else(|| AppError::not_found("Role not found."))
}

fn ensure_role_matches_scope(role: &Role, tenant_id: Option<Uuid>) -> Result<(), AppError> {
    if tenant_id.is_some() && !role.is_tenant_scoped() {
        return Err(AppError::forbidden(
            "Only tenant roles can be used in tenant context.",
        ));
    }

    if tenant_id.is_none() && role.is_tenant_scoped() {
        return Err(AppError::forbidden(
            "Tenant-scoped roles require a tenant context.",
        ));
    }

    Ok(())
}

async fn fetch_user(
    pool: &PgPool,
    user_id: Uuid,
    tenant_id: Option<Uuid>,
) -> Result<User, AppError> {
    match tenant_id {
        Some(tenant_id) => sqlx::query_as::<_, User>(
            r#"
            SELECT u.id, u.email, u.password_hash, u.first_name, u.last_name, u.role_id, u.is_active, u.is_verified, u.created_at, u.updated_at
            FROM users u
            INNER JOIN tenant_members tm ON tm.user_id = u.id
            WHERE u.id = $1
              AND tm.tenant_id = $2
              AND tm.is_active = TRUE
            "#,
        )
        .bind(user_id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| AppError::not_found("User not found.")),
        None => sqlx::query_as::<_, User>(
            "SELECT id, email, password_hash, first_name, last_name, role_id, is_active, is_verified, created_at, updated_at FROM users WHERE id = $1",
        )
        .bind(user_id)
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| AppError::not_found("User not found.")),
    }
}

#[derive(Serialize)]
struct RoleOut {
    id: Uuid,
    name: String,
    description: String,
    created_at: DateTime<Utc>,
}

#[derive(Serialize)]
struct PermOut {
    id: Uuid,
    name: String,
    description: String,
    created_at: DateTime<Utc>,
}

#[derive(Serialize)]
struct UserOut {
    id: Uuid,
    email: String,
    first_name: String,
    last_name: String,
    is_active: bool,
    is_verified: bool,
    tenant_id: Option<Uuid>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

fn user_to_out(u: &User, tenant_id: Option<Uuid>) -> UserOut {
    UserOut {
        id: u.id,
        email: u.email.clone(),
        first_name: u.first_name.clone(),
        last_name: u.last_name.clone(),
        is_active: u.is_active,
        is_verified: u.is_verified,
        tenant_id,
        created_at: u.created_at,
        updated_at: u.updated_at,
    }
}

async fn list_roles(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthUser>,
    tenant_context: Option<Extension<TenantContext>>,
) -> Response {
    match list_roles_inner(&state, auth.user_id, tenant_scope(&tenant_context)).await {
        Ok(response) => response,
        Err(error) => error.into_response(),
    }
}

async fn list_roles_inner(
    state: &AppState,
    user_id: Uuid,
    tenant_id: Option<Uuid>,
) -> Result<Response, AppError> {
    let permissions = tenant_permissions(tenant_id, "roles.manage", "tenant:manage");
    require_any_perm(&state.pool, user_id, tenant_id, &permissions).await?;

    let roles = match tenant_id {
        Some(_) => Role::tenant_roles(&state.pool).await?,
        None => Role::global_roles(&state.pool).await?,
    };

    Ok(ok(roles
        .into_iter()
        .map(|role| RoleOut {
            id: role.id,
            name: role.name,
            description: role.description,
            created_at: role.created_at,
        })
        .collect::<Vec<_>>())
    .into_response())
}

async fn list_permissions(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthUser>,
    tenant_context: Option<Extension<TenantContext>>,
) -> Response {
    match list_permissions_inner(&state, auth.user_id, tenant_scope(&tenant_context)).await {
        Ok(response) => response,
        Err(error) => error.into_response(),
    }
}

async fn list_permissions_inner(
    state: &AppState,
    user_id: Uuid,
    tenant_id: Option<Uuid>,
) -> Result<Response, AppError> {
    let permissions = tenant_permissions(tenant_id, "roles.manage", "tenant:manage");
    require_any_perm(&state.pool, user_id, tenant_id, &permissions).await?;

    let all_permissions = Permission::all(&state.pool).await?;
    Ok(ok(all_permissions
        .into_iter()
        .map(|permission| PermOut {
            id: permission.id,
            name: permission.name,
            description: permission.description,
            created_at: permission.created_at,
        })
        .collect::<Vec<_>>())
    .into_response())
}

async fn get_role_permissions(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthUser>,
    tenant_context: Option<Extension<TenantContext>>,
    Path(role_id): Path<Uuid>,
) -> Response {
    match get_role_permissions_inner(&state, auth.user_id, tenant_scope(&tenant_context), role_id)
        .await
    {
        Ok(response) => response,
        Err(error) => error.into_response(),
    }
}

async fn get_role_permissions_inner(
    state: &AppState,
    user_id: Uuid,
    tenant_id: Option<Uuid>,
    role_id: Uuid,
) -> Result<Response, AppError> {
    let permissions = tenant_permissions(tenant_id, "roles.manage", "tenant:manage");
    require_any_perm(&state.pool, user_id, tenant_id, &permissions).await?;

    let role = load_role(&state.pool, role_id).await?;
    ensure_role_matches_scope(&role, tenant_id)?;

    let role_permissions = Permission::find_by_role_id(&state.pool, role_id).await?;
    Ok(ok(role_permissions
        .into_iter()
        .map(|permission| PermOut {
            id: permission.id,
            name: permission.name,
            description: permission.description,
            created_at: permission.created_at,
        })
        .collect::<Vec<_>>())
    .into_response())
}

async fn assign_permission_to_role(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthUser>,
    tenant_context: Option<Extension<TenantContext>>,
    Json(payload): Json<RolePermReq>,
) -> Response {
    match assign_permission_to_role_inner(
        &state,
        auth.user_id,
        tenant_scope(&tenant_context),
        payload,
    )
    .await
    {
        Ok(response) => response,
        Err(error) => error.into_response(),
    }
}

async fn assign_permission_to_role_inner(
    state: &AppState,
    user_id: Uuid,
    tenant_id: Option<Uuid>,
    payload: RolePermReq,
) -> Result<Response, AppError> {
    require_any_perm(&state.pool, user_id, tenant_id, &["roles.manage"]).await?;
    if tenant_id.is_some() {
        return Err(AppError::forbidden(
            "Tenant-scoped role permissions are seeded and cannot be changed here.",
        ));
    }

    let role = load_role(&state.pool, payload.role_id).await?;
    ensure_role_matches_scope(&role, tenant_id)?;
    Permission::assign_to_role(&state.pool, payload.role_id, payload.permission_id).await?;

    Ok(ok(serde_json::json!({"message": "Permission assigned to role."})).into_response())
}

async fn list_users(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthUser>,
    tenant_context: Option<Extension<TenantContext>>,
) -> Response {
    match list_users_inner(&state, auth.user_id, tenant_scope(&tenant_context)).await {
        Ok(response) => response,
        Err(error) => error.into_response(),
    }
}

async fn list_users_inner(
    state: &AppState,
    user_id: Uuid,
    tenant_id: Option<Uuid>,
) -> Result<Response, AppError> {
    let permissions = tenant_permissions(tenant_id, "users.read", "tenant:members:read");
    require_any_perm(&state.pool, user_id, tenant_id, &permissions).await?;

    let users = match tenant_id {
        Some(tenant_id) => sqlx::query_as::<_, User>(
            r#"
            SELECT DISTINCT u.id, u.email, u.password_hash, u.first_name, u.last_name, u.role_id, u.is_active, u.is_verified, u.created_at, u.updated_at
            FROM users u
            INNER JOIN tenant_members tm ON tm.user_id = u.id
            WHERE tm.tenant_id = $1
              AND tm.is_active = TRUE
            ORDER BY u.created_at DESC
            "#,
        )
        .bind(tenant_id)
        .fetch_all(&state.pool)
        .await?,
        None => sqlx::query_as::<_, User>(
            "SELECT id, email, password_hash, first_name, last_name, role_id, is_active, is_verified, created_at, updated_at FROM users ORDER BY created_at DESC",
        )
        .fetch_all(&state.pool)
        .await?,
    };

    Ok(ok(users
        .iter()
        .map(|user| user_to_out(user, tenant_id))
        .collect::<Vec<_>>())
    .into_response())
}

async fn get_user(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthUser>,
    tenant_context: Option<Extension<TenantContext>>,
    Path(user_id): Path<Uuid>,
) -> Response {
    match get_user_inner(&state, auth.user_id, tenant_scope(&tenant_context), user_id).await {
        Ok(response) => response,
        Err(error) => error.into_response(),
    }
}

async fn get_user_inner(
    state: &AppState,
    auth_user_id: Uuid,
    tenant_id: Option<Uuid>,
    user_id: Uuid,
) -> Result<Response, AppError> {
    let permissions = tenant_permissions(tenant_id, "users.read", "tenant:members:read");
    require_any_perm(&state.pool, auth_user_id, tenant_id, &permissions).await?;

    let user = fetch_user(&state.pool, user_id, tenant_id).await?;
    Ok(ok(user_to_out(&user, tenant_id)).into_response())
}

async fn update_user(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthUser>,
    tenant_context: Option<Extension<TenantContext>>,
    Path(user_id): Path<Uuid>,
    Json(payload): Json<UserUpdateReq>,
) -> Response {
    match update_user_inner(
        &state,
        auth.user_id,
        tenant_scope(&tenant_context),
        user_id,
        payload,
    )
    .await
    {
        Ok(response) => response,
        Err(error) => error.into_response(),
    }
}

async fn update_user_inner(
    state: &AppState,
    auth_user_id: Uuid,
    tenant_id: Option<Uuid>,
    user_id: Uuid,
    payload: UserUpdateReq,
) -> Result<Response, AppError> {
    let permissions = tenant_permissions(tenant_id, "users.write", "tenant:manage");
    require_any_perm(&state.pool, auth_user_id, tenant_id, &permissions).await?;

    let existing_user = fetch_user(&state.pool, user_id, tenant_id).await?;
    let first_name = payload.first_name.unwrap_or(existing_user.first_name);
    let last_name = payload.last_name.unwrap_or(existing_user.last_name);
    let is_active = payload.is_active.unwrap_or(existing_user.is_active);

    sqlx::query(
        "UPDATE users SET first_name = $1, last_name = $2, is_active = $3, updated_at = NOW() WHERE id = $4",
    )
    .bind(&first_name)
    .bind(&last_name)
    .bind(is_active)
    .bind(user_id)
    .execute(&state.pool)
    .await?;

    let updated_user = fetch_user(&state.pool, user_id, tenant_id).await?;
    Ok(ok(user_to_out(&updated_user, tenant_id)).into_response())
}

async fn get_user_permissions(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthUser>,
    tenant_context: Option<Extension<TenantContext>>,
    Path(target_id): Path<Uuid>,
) -> Response {
    match get_user_permissions_inner(
        &state,
        auth.user_id,
        tenant_scope(&tenant_context),
        target_id,
    )
    .await
    {
        Ok(response) => response,
        Err(error) => error.into_response(),
    }
}

async fn get_user_permissions_inner(
    state: &AppState,
    auth_user_id: Uuid,
    tenant_id: Option<Uuid>,
    target_id: Uuid,
) -> Result<Response, AppError> {
    let permissions = tenant_permissions(tenant_id, "users.read", "tenant:members:read");
    require_any_perm(&state.pool, auth_user_id, tenant_id, &permissions).await?;

    let _ = fetch_user(&state.pool, target_id, tenant_id).await?;
    let user_permissions = Permission::find_by_user_id(&state.pool, target_id, tenant_id).await?;
    Ok(ok(user_permissions
        .into_iter()
        .map(|permission| PermOut {
            id: permission.id,
            name: permission.name,
            description: permission.description,
            created_at: permission.created_at,
        })
        .collect::<Vec<_>>())
    .into_response())
}

async fn assign_role_to_user(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthUser>,
    tenant_context: Option<Extension<TenantContext>>,
    Json(payload): Json<UserRoleReq>,
) -> Response {
    match assign_role_to_user_inner(&state, auth.user_id, tenant_scope(&tenant_context), payload)
        .await
    {
        Ok(response) => response,
        Err(error) => error.into_response(),
    }
}

async fn assign_role_to_user_inner(
    state: &AppState,
    auth_user_id: Uuid,
    tenant_id: Option<Uuid>,
    payload: UserRoleReq,
) -> Result<Response, AppError> {
    let role = load_role(&state.pool, payload.role_id).await?;
    ensure_role_matches_scope(&role, tenant_id)?;

    match tenant_id {
        Some(tenant_id) => {
            require_any_perm(
                &state.pool,
                auth_user_id,
                Some(tenant_id),
                &["roles.manage", "tenant:manage"],
            )
            .await?;
            let updated = UserRoleModel::assign_tenant(
                &state.pool,
                tenant_id,
                payload.user_id,
                payload.role_id,
            )
            .await?;
            if !updated {
                return Err(AppError::not_found("User not found in tenant."));
            }
        }
        None => {
            require_any_perm(&state.pool, auth_user_id, None, &["roles.manage"]).await?;
            let _ = fetch_user(&state.pool, payload.user_id, None).await?;
            UserRoleModel::assign_global(&state.pool, payload.user_id, payload.role_id).await?;
        }
    }

    Ok(ok(serde_json::json!({"message": "Role assigned to user."})).into_response())
}

#[derive(Deserialize)]
struct RolePermReq {
    role_id: Uuid,
    permission_id: Uuid,
}

#[derive(Deserialize)]
struct UserRoleReq {
    user_id: Uuid,
    role_id: Uuid,
}

#[derive(Deserialize)]
struct UserUpdateReq {
    first_name: Option<String>,
    last_name: Option<String>,
    is_active: Option<bool>,
}
