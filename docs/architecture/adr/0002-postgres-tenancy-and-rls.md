# ADR-0002: PostgreSQL tenant context and row-level security

- **Status:** Accepted for the Phase 1 schema
- **Context:** Every organization-owned row requires tenant isolation. The PRD calls for forced RLS and warns that superusers/table owners can bypass it.
- **Decision:** Every tenant row carries `org_id`; composite keys/foreign keys keep references in one organization. Each request transaction sets `app.org_id` with transaction-local `set_config`; forced RLS uses that value. Application DB roles must be separate `NOBYPASSRLS` roles and must not own tables.
- **Consequences:** Migrations run with a dedicated owner role; runtime credentials are independently provisioned. Tests must include negative cross-org access. RLS does not replace site/group authorization.
- **Verification (updated 2026-10-30):** Two places provision the roles: `deploy/compose/init/001-runtime-roles.sh` creates `bg_migration` and `bg_api`, and CI creates the same pair. `tests/integration/test_postgres_tenant_rls.py` exercises cross-organization isolation. CI rehearses migration rollback (`downgrade base` then `upgrade head`). Exception: the embedded collector/evaluator workers and the seed tools need cross-organization access. In development they use the PostgreSQL superuser via `BG_WORKER_DATABASE_URL`. A dedicated worker role is still open.

