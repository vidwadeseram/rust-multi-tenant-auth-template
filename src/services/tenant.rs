use crate::{errors::AppError, models::tenant::Tenant};
use chrono::Utc;
use sqlx::{PgPool, Row, migrate::Migrator};
use uuid::Uuid;

pub static BASE_MIGRATOR: Migrator = sqlx::migrate!("./migrations");
#[allow(dead_code)]
pub static TENANT_MIGRATOR: Migrator = sqlx::migrate!("./migrations/tenant");

#[allow(dead_code)]
#[derive(Clone)]
pub struct TenantSchemaService {
    pool: PgPool,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct TenantContext {
    pub tenant_id: Uuid,
    pub user_id: Option<Uuid>,
}

impl TenantSchemaService {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn create_tenant_record(
        &self,
        owner_id: Uuid,
        name: &str,
        slug: &str,
        tenant_role_id: Uuid,
    ) -> Result<Tenant, AppError> {
        let tenant = sqlx::query_as::<_, Tenant>(
            r#"
            INSERT INTO tenants (id, name, slug, owner_id, is_active)
            VALUES ($1, $2, $3, $4, TRUE)
            RETURNING id, name, slug, owner_id, is_active, created_at, updated_at
            "#,
        )
        .bind(Uuid::new_v4())
        .bind(name)
        .bind(slug)
        .bind(owner_id)
        .fetch_one(&self.pool)
        .await?;

        sqlx::query(
            r#"
            INSERT INTO tenant_members (id, tenant_id, user_id, role_id, is_active)
            VALUES ($1, $2, $3, $4, TRUE)
            "#,
        )
        .bind(Uuid::new_v4())
        .bind(tenant.id)
        .bind(owner_id)
        .bind(tenant_role_id)
        .execute(&self.pool)
        .await?;

        Ok(tenant)
    }

    #[allow(dead_code)]
    pub async fn ensure_tenant_schema(&self, tenant_id: Uuid) -> Result<(), AppError> {
        let schema_name = Self::schema_name(tenant_id);
        let create_statement = format!("CREATE SCHEMA IF NOT EXISTS \"{schema_name}\"");

        let mut connection = self.pool.acquire().await?;
        sqlx::query(&create_statement)
            .execute(&mut *connection)
            .await?;

        let search_path_statement = format!("SET search_path TO \"{schema_name}\", public");
        sqlx::query(&search_path_statement)
            .execute(&mut *connection)
            .await?;

        TENANT_MIGRATOR.run(&mut *connection).await?;
        Ok(())
    }

    pub async fn tenant_exists(&self, tenant_id: Uuid) -> Result<bool, AppError> {
        let exists = sqlx::query_scalar::<_, bool>(
            r#"
            SELECT EXISTS(
                SELECT 1 FROM tenants WHERE id = $1 AND is_active = TRUE
            )
            "#,
        )
        .bind(tenant_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(exists)
    }

    pub async fn validate_membership(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<bool, AppError> {
        let exists = sqlx::query_scalar::<_, bool>(
            r#"
            SELECT EXISTS(
                SELECT 1
                FROM tenant_members tm
                INNER JOIN tenants t ON t.id = tm.tenant_id
                WHERE tm.tenant_id = $1
                  AND tm.user_id = $2
                  AND tm.is_active = TRUE
                  AND t.is_active = TRUE
            )
            "#,
        )
        .bind(tenant_id)
        .bind(user_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(exists)
    }

    pub async fn first_membership_tenant(&self, user_id: Uuid) -> Result<Option<Uuid>, AppError> {
        let tenant_id = sqlx::query_scalar::<_, Uuid>(
            r#"
            SELECT tm.tenant_id
            FROM tenant_members tm
            INNER JOIN tenants t ON t.id = tm.tenant_id
            WHERE tm.user_id = $1
              AND tm.is_active = TRUE
              AND t.is_active = TRUE
            ORDER BY tm.joined_at ASC
            LIMIT 1
            "#,
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(tenant_id)
    }

    pub async fn resolve_context(
        &self,
        tenant_id: Uuid,
        user_id: Option<Uuid>,
    ) -> Result<Option<TenantContext>, AppError> {
        if !self.tenant_exists(tenant_id).await? {
            return Err(AppError::tenant_access_denied());
        }

        if let Some(user_id) = user_id {
            if !self.validate_membership(tenant_id, user_id).await? {
                return Err(AppError::tenant_access_denied());
            }
        }

        Ok(Some(TenantContext { tenant_id, user_id }))
    }

    #[allow(dead_code)]
    pub fn schema_name(tenant_id: Uuid) -> String {
        format!("tenant_{}", tenant_id.as_simple())
    }

    pub fn build_slug(email: &str) -> String {
        let seed = email
            .split('@')
            .next()
            .unwrap_or("tenant")
            .chars()
            .map(|character| {
                if character.is_ascii_alphanumeric() {
                    character.to_ascii_lowercase()
                } else {
                    '-'
                }
            })
            .collect::<String>();

        format!("{}-{}", seed.trim_matches('-'), Utc::now().timestamp())
    }

    pub async fn role_id_by_name(&self, role_name: &str) -> Result<Uuid, AppError> {
        sqlx::query_scalar::<_, Uuid>("SELECT id FROM roles WHERE name = $1")
            .bind(role_name)
            .fetch_one(&self.pool)
            .await
            .map_err(AppError::from)
    }

    #[allow(dead_code)]
    pub async fn tenant_schema_table_exists(&self, schema_name: &str) -> Result<bool, AppError> {
        let exists = sqlx::query(
            r#"
            SELECT EXISTS(
                SELECT 1
                FROM information_schema.tables
                WHERE table_schema = $1
                  AND table_name = 'tenant_settings'
            )
            "#,
        )
        .bind(schema_name)
        .fetch_one(&self.pool)
        .await?
        .try_get::<bool, _>(0)?;

        Ok(exists)
    }
}
