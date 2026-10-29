# Local PostgreSQL setup

BaselineGuard expects PostgreSQL 17 or newer and psycopg 3. The optional local Compose profile runs PostgreSQL 17 bound to loopback on port 55432. Copy `.env.example` to an untracked `.env`, generate three distinct random passwords for `POSTGRES_SUPERUSER_PASSWORD`, `BG_MIGRATION_PASSWORD`, and `BG_APP_PASSWORD`, and set `BG_DATABASE_URL` and `BG_MIGRATION_DATABASE_URL` to their corresponding runtime and migration-role URLs. The initialization script runs only when PostgreSQL first creates its data volume; rotating role passwords later uses an interactive database administration session.

For non-Compose environments, a database administrator must provision separate migration and runtime roles through a secret manager or `psql`'s `\\password` command. Do not put passwords on a command line, in migration files, or in Git. The migration role owns the schema; the runtime `bg_api` role is `NOBYPASSRLS`, does not own tables, and receives only the table-specific privileges required by the migration. Forced RLS predicates depend on transaction-local `app.org_id`.

Alembic reads `BG_MIGRATION_DATABASE_URL` from the shell or `.env`; the API reads `BG_DATABASE_URL`. The checked-in `.env.example` credentials are intentionally invalid placeholders. Provision an organization and a platform administrator identity through a controlled administrative procedure before exercising protected inventory APIs; Phase 2 adds the product identity bootstrap and site management flows.

