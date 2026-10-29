# ADR-0002: PostgreSQL tenant context and row-level security

- **Status:** Accepted for the Phase 1 schema
- **Context:** Every organization-owned row requires tenant isolation. The PRD calls for forced RLS and warns that superusers/table owners can bypass it.
- **Decision:** Every tenant row carries `org_id`; composite keys/foreign keys keep references in one organization. Each request transaction sets `app.org_id` with transaction-local `set_config`; forced RLS uses that value. Application DB roles must be separate `NOBYPASSRLS` roles and must not own tables.
- **Consequences:** Migrations run with a dedicated owner role; runtime credentials are independently provisioned. Tests must include negative cross-org access. RLS does not replace site/group authorization.
- **Open verification:** No project database role/credential has been provisioned locally. Phase 0 database integration and migration rollback remain unverified.

