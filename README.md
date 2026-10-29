# BaselineGuard

BaselineGuard is a self-hosted foundation for deterministic, evidence-centered configuration audits. It is designed to make assessment scope, evidence completeness, policy provenance, and unsupported capabilities visible. It does not change target configuration and does not use AI/ML or paid third-party APIs.

**This repository is an early development build, not a production-ready CIS auditor.** Offline evidence import, deterministic evaluation, findings lifecycle, exceptions, reports, the policy catalog and a polished web UI now work end to end locally. Live collection, Windows/network adapters, schedules, PDF export and required live validation remain incomplete. Deployment is intentionally pending.

## Quick demo (local, no live devices)

With Docker running (PostgreSQL on `127.0.0.1:55432`) and `.env` configured (see below):

```powershell
powershell -File tools/dev.ps1        # migrates, seeds a demo org, starts API + UI
python tools/totp.py                  # current authenticator codes
```

Sign in as organization `northwind`, user `ava` (administrator) or `rowan` (risk approver); the per-database demo password is kept in the ignored local file `data/demo-credentials.json` and is not printed. The demo imports sample evidence for six Ubuntu hosts through the real import, evaluate, findings pipeline (labeled `import`, never live). Embedded workers are a development convenience (`BG_EMBEDDED_WORKERS`); run the collector and evaluator as separate processes otherwise. If port 8000 or 5173 is taken by another service, pass `-ApiPort` / `-WebPort`; the dev script reuses healthy BaselineGuard servers and never terminates processes it did not start.

## Current verified scope

- Core database schema and Alembic migrations, tenant-aware PostgreSQL policies, inventory and scan-request APIs.
- Local password + TOTP session authentication, one-time recovery codes, throttling, CSRF protection, site-scoped roles, and separate policy author/approver checks.
- Declarative, bounded deterministic rule evaluation and an original, independently authored Ubuntu 22.04 demonstration pack (20 controls) with reviewed remediation guidance.
- Offline evidence import, evaluator worker, immutable result sets, findings lifecycle, exceptions with independent approval and expiry.
- Deterministic JSON/HTML/CSV reports with escaping, secret redaction and SHA-256 digests; download is audited.
- React/TypeScript UI: overview with compliance beside completeness, assets, assessments, findings with detail drawer, exceptions, reports, policies; dark and light themes.

The presence of a reader or a passing fixture test is not a live support claim. The only rule content checked in is an original demonstration pack, not CIS benchmark content. Review [`content/compatibility.yaml`](content/compatibility.yaml) and [`docs/adapters/compatibility.md`](docs/adapters/compatibility.md) before treating any platform as supported.

## Requirements and gates

[`PRD.md`](PRD.md) is the product and architecture source of truth. Licensed representative labs and content rights are required before platform support is claimed; those external gates are not satisfied here. Do not call the project production-ready until the PRD's G0-G5 criteria are evidenced.

## Development prerequisites

- Python 3.12+, `uv` (or the existing `.venv`)
- Node.js 24+, Corepack/pnpm
- PostgreSQL 17+ (Compose service binds to `127.0.0.1:55432`)

Copy `.env.example` to `.env` and replace all passwords and the session secret with unique random values. Never commit `.env`.

```powershell
uv sync --all-packages --group dev
corepack pnpm install --frozen-lockfile
docker compose -f deploy/compose/compose.yaml up -d postgres
uv run alembic upgrade head
uv run uvicorn baselineguard_api.main:app --reload --host 127.0.0.1 --port 8000
corepack pnpm --filter @baselineguard/web dev
```

`BG_DATABASE_URL` is the restricted runtime role; `BG_MIGRATION_DATABASE_URL` the schema role. Workers claim jobs across organizations and need a role allowed to do so (`BG_WORKER_DATABASE_URL`; the demo seed uses the local PostgreSQL superuser, which is development-only). More: [`docs/development/local-postgres.md`](docs/development/local-postgres.md), [`docs/user-guide/first-run.md`](docs/user-guide/first-run.md).

## Checks

```powershell
uv run ruff check apps packages tests migrations tools
uv run pytest
corepack pnpm --filter @baselineguard/web typecheck
corepack pnpm --filter @baselineguard/web test
corepack pnpm --filter @baselineguard/web build
corepack pnpm --filter @baselineguard/web test:e2e
```

PostgreSQL integration tests need `BG_MIGRATION_DATABASE_URL` (and `BG_DATABASE_URL`); otherwise they skip. See [`docs/development/verification.md`](docs/development/verification.md).

## Repository map

See [`docs/architecture/repository-map.md`](docs/architecture/repository-map.md). Status record: [`docs/development/project-status.md`](docs/development/project-status.md).

## Safety

Only register authorized targets and scopes. Never use Telnet, disable host/TLS verification, place secrets in source control, or interpret missing evidence as a passing result. See [`SECURITY.md`](SECURITY.md).
