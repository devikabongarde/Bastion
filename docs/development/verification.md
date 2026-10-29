# Development verification record

This is a local development check record for the current repository state. It is not a product release or a live adapter certification. Re-run these checks after code changes.

## Commands run in this workspace

| Check | Command | Result | What it verifies |
|---|---|---|---|
| Python lint | `.venv/Scripts/ruff.exe check apps packages tests migrations` | Pass | Ruff rules on Python application, packages, tests and migrations |
| Python types | `.venv/Scripts/pyright.exe` | Pass, 0 errors/warnings | Configured Python type-check scope |
| Python unit + integration | Set `BG_MIGRATION_DATABASE_URL` and `BG_DATABASE_URL` from local `.env`, then `.venv/Scripts/pytest.exe -q` | 71 passed | Unit/contract tests, report redaction/output tests, cron/DST cases, plus PostgreSQL queue, RLS and local-auth integration tests |
| Migration state | `.venv/Scripts/alembic.exe current` with migration URL | `0003_local_identity (head)` | Configured local PostgreSQL schema is at latest migration |
| Web TypeScript | From `apps/web`: `node_modules/.bin/tsc.cmd -b --pretty false` | Pass | TypeScript project references |
| Web unit | From `apps/web`: `node_modules/.bin/vitest.cmd run` | 3 passed | Current UI library tests |
| Web production build | From `apps/web`: `node_modules/.bin/vite.cmd build` | Pass | Vite production bundle |
| Browser E2E | Root: `apps/web/node_modules/.bin/playwright.cmd test --config apps/web/playwright.config.ts` | 2 passed | Narrow viewport layout and keyboard navigation against synthetic API responses |

Python test run emitted one upstream Starlette/httpx deprecation warning. PostgreSQL tests used the already-installed local PostgreSQL service and local `.env`; secret values were not printed. No production environment or target device was used.

The workspace dependency lock check also passed with `uv lock --check --offline` using a workspace-local uv cache.

## Not verified by these checks

- Windows, Linux, firewall, router or switch live collection, permissions, firmware-specific parsing, CPU/network impact, or held-out accuracy.
- End-to-end scan creation through collection, evidence persistence, rule evaluation, finding lifecycle, report rendering, and rescan resolution.
- PostgreSQL backup/restore, migration downgrade rehearsal, HA/failover, 500/10,000 asset load, retention, disaster recovery or operational RPO/RTO.
- PDF/CSV/HTML/JSON report parity, artifact signatures, content rights, authenticated collector operation, security review, or pilot usability.
- Offline installation without cached dependencies, deployment packaging, container image hardening, and production secret provisioning.

Corepack package-manager invocation was blocked by the managed environment denying writes to the user-level Corepack cache. Equivalent installed frontend binaries ran the type check, unit suite, production build and E2E suite directly. Use the pinned pnpm workflow in CI or a normal developer environment to verify package-manager reproducibility.
