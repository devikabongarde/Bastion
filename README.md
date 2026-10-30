# Bastion: every control, verified

Bastion (internal package name `baselineguard`) is a self-hosted, **deterministic configuration-compliance auditor**. It collects facts from Linux, Windows, Cisco IOS XE and FortiGate systems using fixed, read-only commands and evaluates them against versioned rule packs. It records every result with tamper-evident digests and keeps the evidence behind each verdict. It never changes target configuration, and no AI/ML takes part in evaluation.

> Status: working demo build. The rule content is original, CIS-*style* organizational guidance, **not** licensed CIS Benchmark content. See [project status](docs/development/project-status.md) for what is verified and the known defects.

## Features

- **Live collection**
  - Ubuntu over SSH (`linux-ssh`), Cisco IOS XE routers and switches (`cisco-iosxe`) and FortiGate (`fortigate-ssh`) via fixed command tables.
  - Local Windows audit of the Bastion host (`windows-local`).
  - Offline evidence import.
- **Safe-by-default connections**
  - Per-site CIDR, port and DNS allow-lists with pinned-IP connections.
  - SSH host-key fingerprint confirmation and pinning; unknown or changed keys are refused.
  - Credentials encrypted at rest.
- **Deterministic evaluation:** 103 controls in 4 packs. Results are `PASS` / `FAIL` / `UNKNOWN` / `NOT_APPLICABLE` / `ERROR`. Missing evidence never counts as a pass.
- **Evidence integrity**
  - SHA-256 snapshot digests and an engine digest binding policy, packs and snapshot.
  - Immutable result tables.
  - A per-organization SHA-256 audit hash chain.
- **Workflow**
  - A findings lifecycle (open, resolve, reopen, owner, due date).
  - Dual-custody risk exceptions with expiry.
  - Policy drafts with impact preview and independent approval.
  - Cron schedules.
  - JSON, HTML, CSV and PDF reports.
- **Multi-tenant:** `org_id` on every row with **forced PostgreSQL row-level security**, plus site-scoped roles.
- **Authentication:** local password + TOTP MFA, recovery codes, CSRF-protected cookie sessions, rate limiting. An optional demo login exists for presentations.
- **Web console:** a landing page and the Bastion console (Overview, Assets, Assessments, Findings, Exceptions, Schedules, Reports, Policies), with light and dark themes.

## Quick start (Windows, development)

Prerequisites: Python 3.12+ with `uv`, Node 24 with pnpm via corepack, and Docker.

```powershell
uv sync --all-packages --group dev
corepack pnpm install --frozen-lockfile
Copy-Item .env.example .env        # then replace every placeholder; see docs/development/local-setup.md
docker compose -f deploy/compose/compose.yaml up -d
.\.venv\Scripts\python.exe tools/seed_demo.py          # migrate + demo org "northwind" (users ava, rowan)

# separate terminals:
.\.venv\Scripts\python.exe -m baselineguard_api        # API :8000 (BG_EMBEDDED_WORKERS=true runs the workers)
.\.venv\Scripts\python.exe tools/mock_targets.py       # optional mock SSH devices on 127.0.0.1:2222
corepack pnpm --filter @baselineguard/web dev          # console :5173

.\.venv\Scripts\python.exe tools/sync_demo.py --load   # full demo fleet + a live scan
.\.venv\Scripts\python.exe tools/totp.py               # current MFA codes
```

Open http://127.0.0.1:5173 and click **Open console** to reach `/login`. The demo password is stored in `data/demo-credentials.json`. With `BG_DEMO_LOGIN=true`, one-click demo sign-in is available. The full guide is in [docs/development/local-setup.md](docs/development/local-setup.md). To onboard real Ubuntu machines, see [docs/runbooks/ubuntu-lab-onboarding.md](docs/runbooks/ubuntu-lab-onboarding.md).

## Architecture

```
Browser ──► FastAPI (auth, inventory, scans, findings, reports)
               │  per-request txn with app.org_id → PostgreSQL (forced RLS)
               └─ embedded workers: collector ─► adapters ─► normalize ─► encrypted snapshot
                                     evaluator ─► rule engine ─► results / findings
```

A scan enqueues `COLLECT` jobs. The collector leases a job, checks the target against the site scope, runs the adapter and stores a digested snapshot. The evaluator then applies the published policy and writes immutable results and findings. Details: [architecture overview](docs/architecture/overview.md), [data model](docs/architecture/data-model.md), [API](docs/api/current-api.md), [adapters](docs/adapters/compatibility.md), [threat model](docs/architecture/threat-model.md). Index: [docs/README.md](docs/README.md).

## Tech stack

| Layer | Technology |
|---|---|
| Backend | Python 3.12, FastAPI, SQLAlchemy 2, Alembic, Pydantic v2, psycopg 3, paramiko, argon2-cffi, cryptography (AES-GCM, Ed25519), structlog |
| Database | PostgreSQL 17 with forced row-level security |
| Frontend | React 19, TypeScript, Vite 8, Tailwind CSS 4, TanStack Query, React Router 7 |
| Tooling | uv workspace, pnpm workspace, Ruff, Pyright, pytest, Vitest, Playwright, GitHub Actions |

## Project layout

| Path | Contents |
|---|---|
| `apps/api` | FastAPI service, auth, routes, embedded workers, schedule tick |
| `apps/collector`, `apps/evaluator` | Collection and evaluation workers |
| `apps/reporter`, `apps/scheduler` | Report renderers; cron and queue primitives |
| `apps/web` | Bastion web console and landing page |
| `packages/*` | adapters, contracts, credentials, domain, evidence, persistence, rule_engine |
| `content/` | Rule packs, remediation catalogs, pack schema |
| `migrations/` | Alembic revisions 0001–0006 |
| `tools/` | Seed/sync, mock devices, TOTP, local audit, pack builder, Ubuntu lab setup and preflight |
| `deploy/` | Dev PostgreSQL compose; Dockerfiles |
| `docs/` | Documentation |

See [docs/architecture/repository-map.md](docs/architecture/repository-map.md) for more detail.

## Testing

```powershell
uv run ruff check apps packages tests migrations tools
uv run pyright
uv run pytest                                   # integration tests need BG_DATABASE_URL + BG_MIGRATION_DATABASE_URL
corepack pnpm --filter @baselineguard/web typecheck
corepack pnpm --filter @baselineguard/web test
corepack pnpm --filter @baselineguard/web build
corepack pnpm --filter @baselineguard/web test:e2e
```

On Windows, add `--basetemp=./test-results/pytmp` to pytest if the system temp directory is not accessible. See [docs/development/verification.md](docs/development/verification.md).

## Safety

Register only systems you are authorized to audit, and use dedicated read-only accounts. Keep `.env` and `data/` out of Git. Never enable `BG_DEMO_LOGIN` or `BG_LAB_TARGETS` outside a demo or lab; both are refused in production. See [SECURITY.md](SECURITY.md).

## License

Apache License 2.0. See [LICENSE](LICENSE) and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
