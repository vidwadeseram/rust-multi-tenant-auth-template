use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

const GLOBAL_ROLE_NAMES: [&str; 3] = ["super_admin", "admin", "user"];
const TENANT_ROLE_NAMES: [&str; 2] = ["tenant_admin", "tenant_member"];

#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Role {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    pub created_at: DateTime<Utc>,
}

impl Role {
    pub async fn all(pool: &PgPool) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as::<_, Self>("SELECT id, name, description, created_at FROM roles ORDER BY name")
            .fetch_all(pool)
            .await
    }

    pub async fn find_by_id(pool: &PgPool, role_id: Uuid) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as::<_, Self>(
            "SELECT id, name, description, created_at FROM roles WHERE id = $1",
        )
        .bind(role_id)
        .fetch_optional(pool)
        .await
    }

    pub async fn global_roles(pool: &PgPool) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as::<_, Self>(
            "SELECT id, name, description, created_at FROM roles WHERE name = ANY($1) ORDER BY name",
        )
        .bind(&GLOBAL_ROLE_NAMES)
        .fetch_all(pool)
        .await
    }

    pub async fn tenant_roles(pool: &PgPool) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as::<_, Self>(
            "SELECT id, name, description, created_at FROM roles WHERE name = ANY($1) ORDER BY name",
        )
        .bind(&TENANT_ROLE_NAMES)
        .fetch_all(pool)
        .await
    }

    pub fn is_tenant_scoped(&self) -> bool {
        Self::is_tenant_role_name(&self.name)
    }

    pub fn is_tenant_role_name(role_name: &str) -> bool {
        TENANT_ROLE_NAMES.contains(&role_name)
    }
}
