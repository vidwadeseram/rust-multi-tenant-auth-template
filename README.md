# rust-multi-tenant-auth-template

Axum + SQLx starter for multi-tenant authentication with Docker, PostgreSQL migrations, JWT auth, refresh token rotation, and optional tenant schema provisioning.

## Endpoints

- `GET /health`
- `POST /api/v1/auth/register`
- `POST /api/v1/auth/login`
- `POST /api/v1/auth/refresh`
- `POST /api/v1/auth/logout`
- `GET /api/v1/auth/me`

## Local run

```bash
docker-compose up --build
```

App is exposed on `http://localhost:8004`.
