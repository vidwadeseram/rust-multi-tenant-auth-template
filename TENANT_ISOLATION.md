# Tenant Data Isolation

## Current Approach: Application-Level Filtering

This template uses **application-level tenant isolation**. Every table that holds tenant-scoped data includes a `tenant_id` column, and all queries filter by that column explicitly in the SQL.

Example pattern used throughout the codebase:

```sql
SELECT * FROM users
WHERE tenant_id = $1 AND id = $2;
```

This means isolation correctness depends entirely on the application code always including the `tenant_id` predicate. There is no database-enforced boundary preventing one tenant's data from being read or written by a query that omits the filter.

### Tradeoffs

| Aspect | Application-level filtering |
|---|---|
| Setup complexity | Low — no extra DB configuration needed |
| Portability | Works on any PostgreSQL instance |
| Safety guarantee | Relies on code correctness; a missing `WHERE tenant_id = $1` leaks data |
| Performance | Requires `tenant_id` index on every tenant-scoped table |
| Auditability | Harder to verify isolation without reviewing every query |

---

## Production Alternatives

### 1. Row-Level Security (RLS) — Recommended

PostgreSQL's built-in RLS lets you attach security policies directly to tables. The database enforces them for every query, regardless of application code.

**Enable RLS on a table:**

```sql
ALTER TABLE users ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON users
    USING (tenant_id = current_setting('app.current_tenant_id')::uuid);
```

**Set the tenant context at the start of each request (in a transaction):**

```sql
SET LOCAL app.current_tenant_id = '<tenant-uuid>';
```

**In Rust with sqlx**, run this before your queries:

```rust
sqlx::query("SELECT set_config('app.current_tenant_id', $1, true)")
    .bind(tenant_id.to_string())
    .execute(&pool)
    .await?;
```

With RLS active, a query that omits `WHERE tenant_id = $1` will still only return rows belonging to the current tenant. A superuser or table owner bypasses RLS by default; use `FORCE ROW LEVEL SECURITY` to apply it to owners too:

```sql
ALTER TABLE users FORCE ROW LEVEL SECURITY;
```

PostgreSQL RLS documentation: https://www.postgresql.org/docs/current/ddl-rowsecurity.html

---

### 2. Separate Schema per Tenant

Each tenant gets its own PostgreSQL schema (e.g., `tenant_abc.users`, `tenant_xyz.users`). The `search_path` is set per connection to route queries to the correct schema.

```sql
CREATE SCHEMA tenant_abc;
CREATE TABLE tenant_abc.users ( ... );

SET search_path TO tenant_abc;
SELECT * FROM users;
```

**Tradeoffs:**
- Strong isolation — schemas are independent namespaces
- Schema migrations must be applied to every tenant schema
- Connection pooling is more complex (search_path must be reset per request)
- Practical upper limit of a few thousand tenants before management overhead grows

---

### 3. Separate Database per Tenant

Each tenant has a dedicated PostgreSQL database. The application maintains a connection pool per tenant.

**Tradeoffs:**
- Strongest isolation — full database boundary
- Simplest per-tenant backup and restore
- High operational overhead: connection pools, migrations, monitoring multiply with tenant count
- Suitable only for a small number of high-value tenants

---

## Choosing an Approach

| Tenants | Recommended approach |
|---|---|
| < 10, high-value | Separate database |
| 10 – 1 000 | Separate schema |
| 1 000+ | RLS or application-level filtering |

For most SaaS products starting out, **RLS** offers the best balance: low setup cost, strong database-enforced guarantees, and no schema-per-tenant management overhead.
