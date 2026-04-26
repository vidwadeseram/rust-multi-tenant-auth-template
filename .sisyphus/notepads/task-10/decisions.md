## 2026-04-26
- Kept tenant role assignments in `tenant_members` and reserved `user_roles` for global roles to preserve the current schema and avoid introducing a new tenant-scoped role mapping table.
- Scoped admin user listing, lookup, updates, and effective permission reads by `tenant_id` only when a tenant context header is present.
