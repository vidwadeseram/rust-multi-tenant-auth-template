## 2026-04-26
- Existing Docker volume state caused `sqlx` migration version mismatch for `202604260003`; resetting with `docker-compose down -v` was required before runtime verification.
