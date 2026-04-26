use sqlx::PgPool;
use uuid::Uuid;

pub struct UserRole;

impl UserRole {
    pub async fn assign_global(
        pool: &PgPool,
        user_id: Uuid,
        role_id: Uuid,
    ) -> Result<(), sqlx::Error> {
        let mut transaction = pool.begin().await?;

        sqlx::query("UPDATE users SET role_id = $1, updated_at = NOW() WHERE id = $2")
            .bind(role_id)
            .bind(user_id)
            .execute(&mut *transaction)
            .await?;

        sqlx::query("DELETE FROM user_roles WHERE user_id = $1")
            .bind(user_id)
            .execute(&mut *transaction)
            .await?;

        sqlx::query(
            "INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
        )
        .bind(user_id)
        .bind(role_id)
        .execute(&mut *transaction)
        .await?;

        transaction.commit().await?;
        Ok(())
    }

    pub async fn assign_tenant(
        pool: &PgPool,
        tenant_id: Uuid,
        user_id: Uuid,
        role_id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            "UPDATE tenant_members SET role_id = $1 WHERE tenant_id = $2 AND user_id = $3 AND is_active = TRUE",
        )
        .bind(role_id)
        .bind(tenant_id)
        .bind(user_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    pub async fn remove(pool: &PgPool, user_id: Uuid, role_id: Uuid) -> Result<(), sqlx::Error> {
        sqlx::query("DELETE FROM user_roles WHERE user_id = $1 AND role_id = $2")
            .bind(user_id)
            .bind(role_id)
            .execute(pool)
            .await?;
        Ok(())
    }
}
