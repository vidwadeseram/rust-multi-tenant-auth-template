use crate::errors::StartupError;
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::{env, path::Path};
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Clone, Debug)]
pub struct Settings {
    pub database_url: String,
    pub jwt_secret: String,
    pub jwt_algorithm: String,
    pub jwt_access_expire_minutes: i64,
    pub jwt_refresh_expire_days: i64,
    pub smtp_host: String,
    pub smtp_port: u16,
    pub smtp_sender: String,
    pub app_port: u16,
    pub bind_port_override: Option<u16>,
    pub multi_tenant_mode: String,
}

impl Settings {
    pub fn load() -> Result<Self, StartupError> {
        Self::load_env_file(".env")?;
        Self::load_env_file(".env.example")?;

        let settings = Self {
            database_url: Self::required("DATABASE_URL")?,
            jwt_secret: Self::required("JWT_SECRET")?,
            jwt_algorithm: Self::optional("JWT_ALGORITHM", "HS256")?,
            jwt_access_expire_minutes: Self::optional_parse("JWT_ACCESS_EXPIRE_MINUTES", 15)?,
            jwt_refresh_expire_days: Self::optional_parse("JWT_REFRESH_EXPIRE_DAYS", 7)?,
            smtp_host: Self::optional("SMTP_HOST", "mailhog")?,
            smtp_port: Self::optional_parse("SMTP_PORT", 1025)?,
            smtp_sender: Self::optional("SMTP_SENDER", "no-reply@example.com")?,
            app_port: Self::optional_parse("APP_PORT", 8004)?,
            bind_port_override: Self::optional_parse_opt("BIND_PORT")?,
            multi_tenant_mode: Self::optional("MULTI_TENANT_MODE", "row")?,
        };

        if settings.multi_tenant_mode != "row" && settings.multi_tenant_mode != "schema" {
            return Err(StartupError::Config(
                "MULTI_TENANT_MODE must be 'row' or 'schema'".to_string(),
            ));
        }

        Ok(settings)
    }

    pub async fn database_pool(&self) -> Result<PgPool, StartupError> {
        PgPoolOptions::new()
            .max_connections(10)
            .connect(&self.database_url)
            .await
            .map_err(StartupError::Database)
    }

    pub fn bind_port(&self) -> u16 {
        self.bind_port_override.unwrap_or(self.app_port)
    }

    pub fn init_tracing(&self) {
        let filter = EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new("info,tower_http=info"));

        tracing_subscriber::registry()
            .with(filter)
            .with(fmt::layer())
            .try_init()
            .ok();
    }

    fn load_env_file(path: &str) -> Result<(), StartupError> {
        if Path::new(path).exists() {
            dotenvy::from_filename(path)
                .map(|_| ())
                .map_err(StartupError::EnvFile)?;
        }

        Ok(())
    }

    fn required(key: &str) -> Result<String, StartupError> {
        env::var(key).map_err(|_| StartupError::Config(format!("Missing required env var {key}")))
    }

    fn optional(key: &str, default: &str) -> Result<String, StartupError> {
        Ok(env::var(key).unwrap_or_else(|_| default.to_string()))
    }

    fn optional_parse<T>(key: &str, default: T) -> Result<T, StartupError>
    where
        T: std::str::FromStr + Copy,
    {
        match env::var(key) {
            Ok(value) => value
                .parse::<T>()
                .map_err(|_| StartupError::Config(format!("Invalid value for {key}"))),
            Err(_) => Ok(default),
        }
    }

    fn optional_parse_opt<T>(key: &str) -> Result<Option<T>, StartupError>
    where
        T: std::str::FromStr,
    {
        match env::var(key) {
            Ok(value) => value
                .parse::<T>()
                .map(Some)
                .map_err(|_| StartupError::Config(format!("Invalid value for {key}"))),
            Err(_) => Ok(None),
        }
    }
}
