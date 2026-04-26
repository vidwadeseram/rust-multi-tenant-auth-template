use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Clone, Debug, sqlx::FromRow)]
pub struct Permission {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    pub created_at: DateTime<Utc>,
}

impl Permission {
    pub async fn all(pool: &PgPool) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as::<_, Self>("SELECT id, name, description, created_at FROM permissions ORDER BY name")
            .fetch_all(pool)
            .await
    }

    pub async fn find_by_name(pool: &PgPool, name: &str) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as::<_, Self>("SELECT id, name, description, created_at FROM permissions WHERE name = $1")
            .bind(name)
            .fetch_optional(pool)
            .await
    }

    pub async fn find_by_user_id(
        pool: &PgPool,
        user_id: Uuid,
        tenant_id: Option<Uuid>,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as::<_, Self>(
            r#"
            SELECT DISTINCT p.id, p.name, p.description, p.created_at
            FROM permissions p
            JOIN role_permissions rp ON rp.permission_id = p.id
            WHERE rp.role_id = (SELECT role_id FROM users WHERE id = $1)
               OR EXISTS (
                    SELECT 1
                    FROM user_roles ur
                    WHERE ur.user_id = $1
                      AND ur.role_id = rp.role_id
               )
               OR (
                    $2::uuid IS NOT NULL
                    AND EXISTS (
                        SELECT 1
                        FROM tenant_members tm
                        WHERE tm.user_id = $1
                          AND tm.tenant_id = $2
                          AND tm.is_active = TRUE
                          AND tm.role_id = rp.role_id
                    )
               )
            ORDER BY p.name
            "#,
        )
        .bind(user_id)
        .bind(tenant_id)
        .fetch_all(pool)
        .await
    }

    pub async fn user_has_permission(
        pool: &PgPool,
        user_id: Uuid,
        permission_name: &str,
        tenant_id: Option<Uuid>,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query_scalar::<_, bool>(
            r#"
            SELECT EXISTS(
                SELECT 1
                FROM permissions p
                JOIN role_permissions rp ON rp.permission_id = p.id
                WHERE p.name = $2
                  AND (
                        rp.role_id = (SELECT role_id FROM users WHERE id = $1)
                     OR EXISTS (
                            SELECT 1
                            FROM user_roles ur
                            WHERE ur.user_id = $1
                              AND ur.role_id = rp.role_id
                        )
                     OR (
                            $3::uuid IS NOT NULL
                            AND EXISTS (
                                SELECT 1
                                FROM tenant_members tm
                                WHERE tm.user_id = $1
                                  AND tm.tenant_id = $3
                                  AND tm.is_active = TRUE
                                  AND tm.role_id = rp.role_id
                            )
                        )
                  )
            )
            "#,
        )
        .bind(user_id)
        .bind(permission_name)
        .bind(tenant_id)
        .fetch_one(pool)
        .await?;
        Ok(result)
    }

    pub async fn find_by_role_id(pool: &PgPool, role_id: Uuid) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as::<_, Self>(
            r#"
            SELECT p.id, p.name, p.description, p.created_at
            FROM permissions p
            JOIN role_permissions rp ON rp.permission_id = p.id
            WHERE rp.role_id = $1
            "#,
        )
        .bind(role_id)
        .fetch_all(pool)
        .await
    }

    pub async fn assign_to_role(pool: &PgPool, role_id: Uuid, permission_id: Uuid) -> Result<(), sqlx::Error> {
        sqlx::query("INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, $2) ON CONFLICT DO NOTHING")
            .bind(role_id)
            .bind(permission_id)
            .execute(pool)
            .await?;
        Ok(())
    }

    pub async fn remove_from_role(pool: &PgPool, role_id: Uuid, permission_id: Uuid) -> Result<(), sqlx::Error> {
        sqlx::query("DELETE FROM role_permissions WHERE role_id = $1 AND permission_id = $2")
            .bind(role_id)
            .bind(permission_id)
            .execute(pool)
            .await?;
        Ok(())
    }
}
