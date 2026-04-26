## 2026-04-26
- Tenant RBAC works cleanly by combining global `users.role_id`/`user_roles` permissions with tenant-scoped `tenant_members.role_id` permissions instead of overloading `user_roles` with tenant IDs.
- Admin endpoints should treat tenant context as explicit via `X-Tenant-ID`; otherwise global RBAC checks become unintentionally tenant-scoped because access tokens already carry a default tenant.
