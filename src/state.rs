use crate::{
    config::Settings,
    services::{auth::AuthService, tenant::TenantSchemaService, token::TokenService},
};
use sqlx::PgPool;

#[derive(Clone)]
pub struct AppState {
    pub token_service: TokenService,
    pub auth_service: AuthService,
    pub tenant_schema_service: TenantSchemaService,
}

impl AppState {
    pub fn new(
        pool: PgPool,
        settings: Settings,
        tenant_schema_service: TenantSchemaService,
    ) -> Self {
        let token_service = TokenService::new(settings.clone());
        let auth_service = AuthService::new(
            pool.clone(),
            settings.clone(),
            token_service.clone(),
            tenant_schema_service.clone(),
        );

        Self {
            token_service,
            auth_service,
            tenant_schema_service,
        }
    }
}
