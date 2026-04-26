use crate::{
    config::Settings,
    mailer::Mailer,
    services::{auth::AuthService, tenant::TenantSchemaService, token::TokenService},
};
use sqlx::PgPool;

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub token_service: TokenService,
    pub auth_service: AuthService,
    pub tenant_schema_service: TenantSchemaService,
    pub mailer: Mailer,
}

impl AppState {
    pub fn new(
        pool: PgPool,
        settings: Settings,
        tenant_schema_service: TenantSchemaService,
    ) -> Self {
        let token_service = TokenService::new(settings.clone());
        let mailer = Mailer::new(&settings.smtp_host, settings.smtp_port, &settings.smtp_sender);
        let auth_service = AuthService::new(
            pool.clone(),
            settings.clone(),
            token_service.clone(),
            tenant_schema_service.clone(),
            mailer.clone(),
        );

        Self {
            pool,
            token_service,
            auth_service,
            tenant_schema_service,
            mailer,
        }
    }
}
