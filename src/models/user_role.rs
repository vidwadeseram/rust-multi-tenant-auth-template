use sqlx::PgPool;
use uuid::Uuid;

pub struct UserRole;

impl UserRole {
    pub async fn assign(pool: &PgPool, user_id: Uuid, role_id: Uuid) -> Result<(), sqlx::Error> {
        sqlx::query("INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2) ON CONFLICT DO NOTHING")
            .bind(user_id)
            .bind(role_id)
            .execute(pool)
            .await?;
        Ok(())
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
