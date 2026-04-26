use axum::{
    Extension, Json, Router,
    extract::{Path, State},
    response::{IntoResponse, Response},
    routing::{delete, get, patch, post},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    errors::AppError,
    middleware::auth::AuthUser,
    models::{role::Role, tenant::Tenant},
    response::{created, ok},
    state::AppState,
};

pub fn tenant_routes() -> Router<AppState> {
    Router::new()
        .route("/create", post(create_tenant))
        .route("/list", get(list_my_tenants))
        .route("/{tenant_id}", get(get_tenant))
        .route("/{tenant_id}", patch(update_tenant))
        .route("/{tenant_id}", delete(delete_tenant))
        .route("/{tenant_id}/members", get(list_members))
        .route("/{tenant_id}/invitations", post(invite_member))
        .route("/{tenant_id}/invitations/accept", post(accept_invitation))
        .route(
            "/{tenant_id}/members/{user_id}/role",
            patch(update_member_role),
        )
        .route("/{tenant_id}/members/{user_id}", delete(remove_member))
}

async fn require_tenant_admin(
    pool: &sqlx::PgPool,
    tenant_id: Uuid,
    user_id: Uuid,
) -> Result<(), AppError> {
    let result = sqlx::query_as::<_, (Uuid, String)>(
        r#"SELECT tm.role_id, r.name FROM tenant_members tm JOIN roles r ON r.id = tm.role_id WHERE tm.tenant_id = $1 AND tm.user_id = $2 AND tm.is_active = TRUE"#
    )
    .bind(tenant_id)
    .bind(user_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| AppError::internal(e.to_string()))?;

    match result {
        Some((_, role_name)) if role_name == "tenant_admin" || role_name == "super_admin" => Ok(()),
        _ => Err(AppError::forbidden(
            "Only tenant admins can perform this action.",
        )),
    }
}

async fn require_membership(
    pool: &sqlx::PgPool,
    tenant_id: Uuid,
    user_id: Uuid,
) -> Result<(), AppError> {
    let is_member = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM tenant_members WHERE tenant_id = $1 AND user_id = $2 AND is_active = TRUE)"
    )
    .bind(tenant_id)
    .bind(user_id)
    .fetch_one(pool)
    .await
    .map_err(|e| AppError::internal(e.to_string()))?;

    if !is_member {
        return Err(AppError::forbidden("You are not a member of this tenant."));
    }
    Ok(())
}

#[derive(Serialize)]
struct TenantOut {
    id: Uuid,
    name: String,
    slug: String,
    owner_id: Uuid,
    is_active: bool,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

fn tenant_to_out(t: &Tenant) -> TenantOut {
    TenantOut {
        id: t.id,
        name: t.name.clone(),
        slug: t.slug.clone(),
        owner_id: t.owner_id,
        is_active: t.is_active,
        created_at: t.created_at,
        updated_at: t.updated_at,
    }
}

#[derive(Serialize)]
struct MemberOut {
    id: Uuid,
    tenant_id: Uuid,
    user_id: Uuid,
    role_id: Uuid,
    is_active: bool,
    joined_at: DateTime<Utc>,
    user_email: Option<String>,
    role_name: Option<String>,
}

#[derive(Deserialize)]
struct CreateTenantReq {
    name: String,
    slug: String,
}

#[derive(Deserialize)]
struct UpdateTenantReq {
    name: Option<String>,
    is_active: Option<bool>,
}

#[derive(Deserialize)]
struct InviteReq {
    email: String,
    role_id: Uuid,
}

#[derive(Deserialize)]
struct AcceptInviteReq {
    token: String,
}

#[derive(Deserialize)]
struct UpdateRoleReq {
    role_id: Uuid,
}

async fn create_tenant(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthUser>,
    Json(payload): Json<CreateTenantReq>,
) -> Response {
    let tenant_admin_role_id = match state
        .tenant_schema_service
        .role_id_by_name("tenant_admin")
        .await
    {
        Ok(id) => id,
        Err(e) => return e.into_response(),
    };

    match state
        .tenant_schema_service
        .create_tenant_record(
            auth.user_id,
            &payload.name,
            &payload.slug.to_lowercase(),
            tenant_admin_role_id,
        )
        .await
    {
        Ok(tenant) => created(tenant_to_out(&tenant)).into_response(),
        Err(e) => AppError::from(e).into_response(),
    }
}

async fn list_my_tenants(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthUser>,
) -> Response {
    match sqlx::query_as::<_, Tenant>(
        r#"SELECT t.id, t.name, t.slug, t.owner_id, t.is_active, t.created_at, t.updated_at
           FROM tenants t
           JOIN tenant_members tm ON tm.tenant_id = t.id
           WHERE tm.user_id = $1 AND tm.is_active = TRUE AND t.is_active = TRUE
           ORDER BY t.created_at DESC"#,
    )
    .bind(auth.user_id)
    .fetch_all(&state.pool)
    .await
    {
        Ok(tenants) => ok(tenants.iter().map(tenant_to_out).collect::<Vec<_>>()).into_response(),
        Err(e) => AppError::from(e).into_response(),
    }
}

async fn get_tenant(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthUser>,
    Path(tenant_id): Path<Uuid>,
) -> Response {
    if let Err(e) = require_membership(&state.pool, tenant_id, auth.user_id).await {
        return e.into_response();
    }
    match sqlx::query_as::<_, Tenant>(
        "SELECT id, name, slug, owner_id, is_active, created_at, updated_at FROM tenants WHERE id = $1 AND is_active = TRUE"
    )
    .bind(tenant_id)
    .fetch_optional(&state.pool)
    .await {
        Ok(Some(t)) => ok(tenant_to_out(&t)).into_response(),
        Ok(None) => AppError::not_found("Tenant not found.").into_response(),
        Err(e) => AppError::from(e).into_response(),
    }
}

async fn update_tenant(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthUser>,
    Path(tenant_id): Path<Uuid>,
    Json(payload): Json<UpdateTenantReq>,
) -> Response {
    if let Err(e) = require_tenant_admin(&state.pool, tenant_id, auth.user_id).await {
        return e.into_response();
    }
    if let Some(ref name) = payload.name {
        let _ = sqlx::query("UPDATE tenants SET name = $1, updated_at = NOW() WHERE id = $2")
            .bind(name)
            .bind(tenant_id)
            .execute(&state.pool)
            .await;
    }
    if let Some(is_active) = payload.is_active {
        let _ = sqlx::query("UPDATE tenants SET is_active = $1, updated_at = NOW() WHERE id = $2")
            .bind(is_active)
            .bind(tenant_id)
            .execute(&state.pool)
            .await;
    }
    match sqlx::query_as::<_, Tenant>(
        "SELECT id, name, slug, owner_id, is_active, created_at, updated_at FROM tenants WHERE id = $1"
    )
    .bind(tenant_id)
    .fetch_one(&state.pool)
    .await {
        Ok(t) => ok(tenant_to_out(&t)).into_response(),
        Err(e) => AppError::from(e).into_response(),
    }
}

async fn delete_tenant(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthUser>,
    Path(tenant_id): Path<Uuid>,
) -> Response {
    if let Err(e) = require_tenant_admin(&state.pool, tenant_id, auth.user_id).await {
        return e.into_response();
    }
    match sqlx::query("UPDATE tenants SET is_active = FALSE, updated_at = NOW() WHERE id = $1")
        .bind(tenant_id)
        .execute(&state.pool)
        .await
    {
        Ok(_) => ok(serde_json::json!({"message": "Tenant deactivated."})).into_response(),
        Err(e) => AppError::from(e).into_response(),
    }
}

async fn list_members(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthUser>,
    Path(tenant_id): Path<Uuid>,
) -> Response {
    if let Err(e) = require_membership(&state.pool, tenant_id, auth.user_id).await {
        return e.into_response();
    }
    match sqlx::query_as::<_, (Uuid, Uuid, Uuid, Uuid, bool, DateTime<Utc>, Option<String>, Option<String>)>(
        r#"SELECT tm.id, tm.tenant_id, tm.user_id, tm.role_id, tm.is_active, tm.joined_at, u.email as user_email, r.name as role_name
           FROM tenant_members tm
           LEFT JOIN users u ON u.id = tm.user_id
           LEFT JOIN roles r ON r.id = tm.role_id
           WHERE tm.tenant_id = $1 AND tm.is_active = TRUE
           ORDER BY tm.joined_at DESC"#
    )
    .bind(tenant_id)
    .fetch_all(&state.pool)
    .await {
        Ok(rows) => ok(rows.into_iter().map(|(id, tid, uid, rid, active, joined, email, rname)| MemberOut {
            id, tenant_id: tid, user_id: uid, role_id: rid, is_active: active, joined_at: joined, user_email: email, role_name: rname,
        }).collect::<Vec<_>>()).into_response(),
        Err(e) => AppError::from(e).into_response(),
    }
}

async fn invite_member(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthUser>,
    Path(tenant_id): Path<Uuid>,
    Json(payload): Json<InviteReq>,
) -> Response {
    if let Err(e) = require_tenant_admin(&state.pool, tenant_id, auth.user_id).await {
        return e.into_response();
    }
    match sqlx::query_as::<_, Role>(
        "SELECT id, name, description, created_at FROM roles WHERE id = $1",
    )
    .bind(payload.role_id)
    .fetch_optional(&state.pool)
    .await
    {
        Ok(Some(_)) => {}
        Ok(None) => return AppError::not_found("Role not found.").into_response(),
        Err(e) => return AppError::from(e).into_response(),
    }

    let raw_token = match generate_token() {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };
    let token_hash = sha256_hex(raw_token.as_bytes());
    let expires_at = Utc::now() + chrono::Duration::days(7);

    match sqlx::query_scalar::<_, Uuid>(
        r#"INSERT INTO tenant_invitations (id, tenant_id, email, role_id, token_hash, expires_at)
           VALUES ($1, $2, $3, $4, $5, $6) RETURNING id"#,
    )
    .bind(Uuid::new_v4())
    .bind(tenant_id)
    .bind(payload.email.to_lowercase())
    .bind(payload.role_id)
    .bind(&token_hash)
    .bind(expires_at)
    .fetch_one(&state.pool)
    .await
    {
        Ok(inv_id) => ok(serde_json::json!({
            "id": inv_id.to_string(),
            "tenant_id": tenant_id.to_string(),
            "email": payload.email,
            "role_id": payload.role_id.to_string(),
            "expires_at": expires_at.to_rfc3339(),
            "token": raw_token,
        }))
        .into_response(),
        Err(e) => AppError::from(e).into_response(),
    }
}

async fn accept_invitation(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthUser>,
    Path(_tenant_id): Path<Uuid>,
    Json(payload): Json<AcceptInviteReq>,
) -> Response {
    let token_hash = sha256_hex(payload.token.as_bytes());

    let invitation = match sqlx::query_as::<_, (Uuid, Uuid, Uuid, Option<DateTime<Utc>>, DateTime<Utc>)>(
        r#"SELECT id, tenant_id, role_id, accepted_at, expires_at FROM tenant_invitations WHERE token_hash = $1 AND accepted_at IS NULL"#
    )
    .bind(&token_hash)
    .fetch_optional(&state.pool)
    .await {
        Ok(Some(inv)) => inv,
        Ok(None) => return AppError::not_found("Invitation not found or already accepted.").into_response(),
        Err(e) => return AppError::from(e).into_response(),
    };

    let (inv_id, inv_tenant_id, role_id, _, expires_at) = invitation;
    if expires_at < Utc::now() {
        return AppError::bad_request("Invitation has expired.").into_response();
    }

    let _ = sqlx::query("UPDATE tenant_invitations SET accepted_at = NOW() WHERE id = $1")
        .bind(inv_id)
        .execute(&state.pool)
        .await;

    let already = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM tenant_members WHERE tenant_id = $1 AND user_id = $2 AND is_active = TRUE)"
    )
    .bind(inv_tenant_id)
    .bind(auth.user_id)
    .fetch_one(&state.pool)
    .await
    .unwrap_or(false);

    if already {
        return AppError::conflict("User is already a member of this tenant.").into_response();
    }

    match sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO tenant_members (id, tenant_id, user_id, role_id, is_active) VALUES ($1, $2, $3, $4, TRUE) RETURNING id"
    )
    .bind(Uuid::new_v4())
    .bind(inv_tenant_id)
    .bind(auth.user_id)
    .bind(role_id)
    .fetch_one(&state.pool)
    .await {
        Ok(member_id) => ok(serde_json::json!({"message": "Invitation accepted.", "member_id": member_id.to_string()})).into_response(),
        Err(e) => AppError::from(e).into_response(),
    }
}

async fn update_member_role(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthUser>,
    Path((tenant_id, user_id)): Path<(Uuid, Uuid)>,
    Json(payload): Json<UpdateRoleReq>,
) -> Response {
    if let Err(e) = require_tenant_admin(&state.pool, tenant_id, auth.user_id).await {
        return e.into_response();
    }
    match sqlx::query("UPDATE tenant_members SET role_id = $1 WHERE tenant_id = $2 AND user_id = $3 AND is_active = TRUE")
        .bind(payload.role_id).bind(tenant_id).bind(user_id).execute(&state.pool).await {
        Ok(result) if result.rows_affected() > 0 => ok(serde_json::json!({"message": "Member role updated."})).into_response(),
        Ok(_) => AppError::not_found("Member not found.").into_response(),
        Err(e) => AppError::from(e).into_response(),
    }
}

async fn remove_member(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthUser>,
    Path((tenant_id, user_id)): Path<(Uuid, Uuid)>,
) -> Response {
    if let Err(e) = require_tenant_admin(&state.pool, tenant_id, auth.user_id).await {
        return e.into_response();
    }
    match sqlx::query("UPDATE tenant_members SET is_active = FALSE WHERE tenant_id = $1 AND user_id = $2 AND is_active = TRUE")
        .bind(tenant_id).bind(user_id).execute(&state.pool).await {
        Ok(result) if result.rows_affected() > 0 => ok(serde_json::json!({"message": "Member removed from tenant."})).into_response(),
        Ok(_) => AppError::not_found("Member not found.").into_response(),
        Err(e) => AppError::from(e).into_response(),
    }
}

fn sha256_hex(input: &[u8]) -> String {
    let digest = Sha256::digest(input);
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest.iter() {
        use std::fmt::Write;
        let _ = write!(out, "{:02x}", byte);
    }
    out
}

fn generate_token() -> Result<String, AppError> {
    use rand::TryRng;
    let mut bytes = [0u8; 32];
    // SysRng is the OS RNG in rand 0.10 (renamed from OsRng). If the OS RNG
    // is unavailable we cannot proceed safely; this matches the previous
    // behaviour which also panicked on failure.
    rand::rngs::SysRng
        .try_fill_bytes(&mut bytes)
        .map_err(|e| {
            log::error!("OS RNG unavailable, cannot generate token: {e}");
            AppError::internal("Failed to generate secure token".into())
        })?;
    Ok(base64_url::encode(&bytes))
}
