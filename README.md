# rust-multi-tenant-auth-template

Production-ready **multi-tenant** authentication API template built with **Axum**, **SQLx**, and **PostgreSQL**. Ships with tenant management, RBAC, email flows, Docker Compose, automated curl tests, and GitHub Actions CI.

Supports configurable tenant isolation via `MULTI_TENANT_MODE` (row-level or schema-per-tenant).

## Features

- **Core Auth** — Register, login, logout, token refresh with JWT (HS256)
- **Email Verification** — Verify-email flow with expiring tokens via SMTP
- **Password Reset** — Forgot-password / reset-password with one-time tokens
- **RBAC** — Role-based access control with permissions, user management, admin endpoints
- **Multi-Tenant** — Tenant CRUD, member management, invitations with expiring tokens
- **Tenant Isolation** — Configurable via `MULTI_TENANT_MODE` (row-level or schema)
- **Docker** — Single `docker compose up` to spin up app + PostgreSQL
- **CI** — GitHub Actions workflow that builds Docker, runs curl tests, and reports status
- **Error Handling** — Structured `AppError` enum with proper HTTP status mapping

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Framework | Axum |
| Database | SQLx (PostgreSQL) |
| Auth | jsonwebtoken (HS256) + argon2 |
| Validation | validator |
| Serialization | serde + serde_json |
| Email | lettre (MailHog for dev) |
| Logging | tracing + tracing-subscriber |
| Errors | thiserror |
| Container | Docker Compose |

## Quick Start

```bash
# Clone
git clone https://github.com/vidwadeseram/rust-multi-tenant-auth-template.git
cd rust-multi-tenant-auth-template

# Configure
cp .env.example .env
# Edit .env — set JWT_SECRET for production

# Launch
docker compose up --build

# API available at http://localhost:8004
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | `postgres://postgres:postgres@db:5432/rust_multi_tenant_auth` | PostgreSQL connection string |
| `JWT_SECRET` | `change-me-to-a-secure-secret` | HMAC secret for JWT signing |
| `JWT_ALGORITHM` | `HS256` | JWT signing algorithm |
| `JWT_ACCESS_EXPIRE_MINUTES` | `15` | Access token lifetime |
| `JWT_REFRESH_EXPIRE_DAYS` | `7` | Refresh token lifetime |
| `SMTP_HOST` | `mailhog` | SMTP server hostname |
| `SMTP_PORT` | `1025` | SMTP server port |
| `SMTP_SENDER` | `no-reply@example.com` | Sender email address |
| `MULTI_TENANT_MODE` | `row` | Tenant isolation: `row` (shared DB) or `schema` (per-tenant) |
| `APP_PORT` | `8004` | Internal application port |
| `BIND_PORT` | `8000` | External bind port |
| `RUST_LOG` | `info` | Log level |

## API Endpoints

### Authentication

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| `POST` | `/api/v1/auth/register` | Register a new user | No |
| `POST` | `/api/v1/auth/login` | Login with email + password | No |
| `POST` | `/api/v1/auth/refresh` | Refresh access token | No (send refresh token) |
| `POST` | `/api/v1/auth/logout` | Logout (invalidates refresh token) | Yes |
| `GET` | `/api/v1/auth/me` | Get current user profile | Yes |
| `POST` | `/api/v1/auth/verify-email` | Verify email with token | No |
| `POST` | `/api/v1/auth/forgot-password` | Request password reset email | No |
| `POST` | `/api/v1/auth/reset-password` | Reset password with token | No |

### Admin & RBAC

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| `GET` | `/api/v1/admin/roles` | List all roles | `super_admin` |
| `GET` | `/api/v1/admin/users` | List all users with roles | `super_admin` |
| `POST` | `/api/v1/admin/users/{id}/roles` | Assign role to user | `super_admin` |
| `DELETE` | `/api/v1/admin/users/{id}/roles` | Remove role from user | `super_admin` |
| `POST` | `/api/v1/admin/roles/{id}/permissions` | Assign permission to role | `super_admin` |

### Tenant Management

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| `POST` | `/api/v1/tenants/create` | Create a new tenant | Yes |
| `GET` | `/api/v1/tenants/list` | List user's tenants | Yes |
| `GET` | `/api/v1/tenants/{id}` | Get tenant details | Tenant member |
| `PUT` | `/api/v1/tenants/{id}` | Update tenant | Tenant admin |
| `DELETE` | `/api/v1/tenants/{id}` | Delete tenant | Tenant admin |
| `GET` | `/api/v1/tenants/{id}/members` | List tenant members | Tenant member |
| `POST` | `/api/v1/tenants/{id}/invite` | Invite user by email | Tenant admin |
| `POST` | `/api/v1/tenants/{id}/accept` | Accept invitation token | Yes |
| `PUT` | `/api/v1/tenants/{id}/members/{uid}/role` | Update member role | Tenant admin |
| `DELETE` | `/api/v1/tenants/{id}/members/{uid}` | Remove member | Tenant admin |

### Health

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/health` | Health check |

## Project Structure

```
rust-multi-tenant-auth-template/
├── src/
│   ├── main.rs              # Axum app + server startup
│   ├── config.rs            # Environment config
│   ├── models/              # SQLx models (User, Tenant, Membership…)
│   ├── handlers/
│   │   ├── auth.rs          # Auth endpoints
│   │   ├── admin.rs         # Admin/RBAC endpoints
│   │   └── tenant.rs        # Tenant management endpoints
│   ├── routes.rs            # Route registration
│   ├── auth.rs              # JWT middleware + password hashing
│   ├── errors.rs            # AppError enum
│   └── email.rs             # SMTP email sender
├── migrations/              # SQLx migrations
├── tests/
│   └── test_api.sh          # Curl-based integration tests
├── docker/
│   └── Dockerfile
├── docker-compose.yml
├── .github/workflows/ci.yml
├── .env.example
├── Cargo.toml
└── README.md
```

## Multi-Tenant Modes

### Row-Level Isolation (`MULTI_TENANT_MODE=row`)
All tenants share the same database tables. A `tenant_id` column on relevant tables enforces isolation at the application/query level. Simpler to manage, good for most use cases.

### Schema-Per-Tenant (`MULTI_TENANT_MODE=schema`)
Each tenant gets its own PostgreSQL schema. Stronger isolation at the database level. Requires schema provisioning on tenant creation.

## Testing

```bash
# Run curl test suite against running instance
bash tests/test_api.sh http://localhost:8004/api/v1
```

The test script covers:
- User registration and login
- Token refresh and logout
- Email verification flow
- Password reset flow
- RBAC (403 without role, 200 with `super_admin`)
- Admin user/role management
- Tenant CRUD operations
- Tenant invitation and member management

## Response Format

All responses follow a consistent structure:

```json
// Success
{
  "data": {
    "user": { "id": "...", "email": "..." },
    "access_token": "...",
    "refresh_token": "..."
  }
}

// Error
{
  "error": {
    "code": "UNAUTHORIZED",
    "message": "Invalid or expired token."
  }
}
```

## License

MIT
