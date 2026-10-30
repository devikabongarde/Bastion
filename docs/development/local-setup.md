# Local development setup

This page covers a Windows (PowerShell) development machine, which is how the project is developed. The same steps work on Linux/macOS with `.venv/bin/python` in place of `.venv\Scripts\python.exe`.

## Prerequisites

| Tool | Version | Notes |
|---|---|---|
| Python | 3.12+ (`requires-python = ">=3.12"`) | Managed through a `uv` workspace (`pyproject.toml` → `[tool.uv.workspace]`) |
| uv | recent | `pip install uv` if missing |
| Node.js | 24 (as in CI) | |
| pnpm | 10.12.4 (`packageManager` in `package.json`) | Enable with `corepack enable pnpm`, or run as `corepack pnpm ...` |
| Docker | Docker Desktop / Engine with Compose | Runs PostgreSQL 17 |


## 1. Install dependencies

```powershell
uv sync --all-packages --group dev        # creates .venv with every workspace package
corepack pnpm install --frozen-lockfile    # web dependencies
```

## 2. Configure `.env`

```powershell
Copy-Item .env.example .env
```

Replace every placeholder with unique random values. Never commit `.env` (it is git-ignored). The API reads `BG_*` settings from `.env` through `pydantic-settings` (`apps/api/src/baselineguard_api/config.py`). Alembic and the tools load `.env` with `python-dotenv`.

| Variable | Read by | Default | Meaning |
|---|---|---|---|
| `POSTGRES_SUPERUSER_PASSWORD` | Compose, `seed_demo.py`, `sync_demo.py` | — (required by Compose) | Password of the `postgres` superuser in the dev container. The seed tools connect as this user, which bypasses RLS. |
| `BG_MIGRATION_PASSWORD` | Compose init script | — (required) | Password for the `bg_migration` role (schema owner) |
| `BG_APP_PASSWORD` | Compose init script | — (required) | Password for the `bg_api` runtime role (`NOBYPASSRLS`, not the owner) |
| `BG_ENVIRONMENT` | API | `development` | `development`, `test` or `production`. `production` enforces a session secret of at least 32 characters (and not a `development-only` value), no API docs, no CORS, and no `BG_DEMO_LOGIN` or `BG_LAB_TARGETS`. |
| `BG_API_HOST` / `BG_API_PORT` | `python -m baselineguard_api` | `127.0.0.1` / `8000` | Bind address |
| `BG_DATABASE_URL` | API | `postgresql+psycopg://bg_api:...@127.0.0.1:5432/baselineguard` | Runtime URL. Use the `bg_api` role and port **55432** for Compose. |
| `BG_MIGRATION_DATABASE_URL` | Alembic (`migrations/env.py`), integration tests | — | Migration-role URL (`bg_migration`). Must use `postgresql+psycopg`. |
| `BG_WORKER_DATABASE_URL` | Embedded workers | falls back to `BG_DATABASE_URL` | Workers claim jobs across organizations, so they need a role that is not limited by RLS. `.env.example` ships a `postgres` superuser URL here (development only); replace its password. With the `bg_api` role, workers see no jobs. |
| `BG_SESSION_SECRET` | API | `development-only-change-this-session-key` | HMAC key for CSRF tokens and throttle keys. Use 32+ random characters. |
| `BG_LOG_LEVEL` | API | `INFO` | DEBUG/INFO/WARNING/ERROR/CRITICAL |
| `BG_DOCS_ENABLED` | API | `false` | Serves `/api/docs` and `/api/openapi.json` (never in production). `tools/dev.ps1` requires it, because it probes the OpenAPI document. |
| `BG_CORS_ORIGINS` | API | `[]` | JSON list. Leave empty; the Vite dev server proxies `/api`, so the browser stays same-origin. |
| `BG_EVIDENCE_ROOT` | API, workers | `./data/evidence` | Encrypted artifact store (snapshots, reports) |
| `BG_MASTER_KEY_FILE` | API, workers, tools | `./data/keys/master.key` | 32-byte local master key. Seals TOTP secrets, credentials and artifacts. Created if missing. Losing it makes existing secrets and evidence unreadable. |
| `BG_PASSWORD_BLOCKLIST_FILE` | `bootstrap` | none | Optional file of disallowed passwords |
| `BG_EMBEDDED_WORKERS` | API | `false` (`true` in `.env.example`) | Run collector, evaluator and schedule loops inside the API process. **Required** for scans and imports to progress (no standalone worker entry point exists). |
| `BG_DEMO_LOGIN` | API | `false` | Enables `/auth/demo-login`, `/auth/demo-code` and the "Quick demo access" buttons |
| `BG_LAB_TARGETS` | API, collector | `false` | Allows loopback targets (the bundled mock device on `127.0.0.1:2222`) |
| `BG_KNOWN_HOSTS_FILE` | API (connect), collector | `./data/known_hosts` | Pinned SSH host keys |
| `BG_API_URL` | Vite dev server | `http://127.0.0.1:8000` | Proxy target for `/api` and `/health` |

A working demo `.env` therefore includes `BG_DOCS_ENABLED=true`, `BG_EMBEDDED_WORKERS=true`, `BG_WORKER_DATABASE_URL=...`, `BG_DEMO_LOGIN=true` and `BG_LAB_TARGETS=true`.

## 3. Start PostgreSQL

```powershell
docker compose -f deploy/compose/compose.yaml up -d
```

This runs `postgres:17-alpine` on `127.0.0.1:55432` with the named volume `baselineguard-postgres`. On first start, `deploy/compose/init/001-runtime-roles.sh` creates `bg_migration` and `bg_api`, makes `bg_migration` the database owner, and grants `bg_api` CONNECT plus default SELECT. Init scripts run only when the data volume is first created. To change a role password later, use an admin `psql` session.

## 4. Apply migrations

```powershell
.\.venv\Scripts\python.exe -m alembic upgrade head    # or: uv run alembic upgrade head
.\.venv\Scripts\python.exe -m alembic current         # expect 0006_live_onboarding_grants (head)
```

## 5. Seed demo data

```powershell
.\.venv\Scripts\python.exe tools/seed_demo.py
```

`seed_demo.py`:

- runs migrations;
- creates the org `northwind` with users `ava` (platform_admin, analyst, scan_operator, auditor, policy_author, inventory_editor, viewer, manual_assessor) and `rowan` (risk_approver, policy_approver, analyst, viewer);
- creates the site "Primary Datacenter" (`10.20.0.0/16`, ports 22/443/5986) and the sample assets;
- registers the four rule packs and publishes the multi-platform policy;
- writes `data/demo-credentials.json` (password and TOTP secrets) and appends `BG_EMBEDDED_WORKERS` and `BG_WORKER_DATABASE_URL` to `.env` if they are absent.

The password is random per database (`secrets.token_urlsafe`). On the existing demo machine it has been set to the value in `USER_MANUAL.md`, which the sign-in form pre-fills.


Then, with the API running (step 6) and the mock device started (step 8):

```powershell
.\.venv\Scripts\python.exe tools/seed_demo.py --load    # imports sample evidence through the API, assigns findings, creates+approves an exception
.\.venv\Scripts\python.exe tools/sync_demo.py           # adds packs/policy revisions, "Security Lab" site (127.0.0.0/8:2222), live lab assets, pins the mock host key
.\.venv\Scripts\python.exe tools/sync_demo.py --load    # imports sample evidence for new assets and runs a real live scan (needs BG_DEMO_LOGIN + BG_LAB_TARGETS)
```

`sync_demo.py` is idempotent and does not touch users, passwords or MFA secrets. It needs `data/mock_ssh_host_rsa.key`, which `tools/mock_targets.py` creates on its first start. Show the current authenticator codes with:

```powershell
.\.venv\Scripts\python.exe tools/totp.py
```

To create a real (non-demo) administrator instead:

```powershell
.\.venv\Scripts\python.exe -m baselineguard_api.bootstrap --organization local --name "Local Organization" --username admin --email admin@example.invalid --roles platform_admin,inventory_editor,scan_operator,policy_author,credential_admin
```

The bootstrap prompts for a password (at least 14 characters) and an authenticator code, and prints recovery codes.

## 6. Run the API

```powershell
.\.venv\Scripts\python.exe -m baselineguard_api
```

The API runs uvicorn on `BG_API_HOST:BG_API_PORT` without reload. With embedded workers enabled, expect the log line `embedded collector and evaluator workers started`. Check it with `GET http://127.0.0.1:8000/health/ready`.

## 7. Run the web console

```powershell
corepack pnpm --filter @baselineguard/web dev     # http://127.0.0.1:5173
```

`/` shows the landing page until you sign in; "Open console" goes to `/login`. See [first run](../user-guide/first-run.md).

## 8. Mock SSH lab devices (optional)

```powershell
.\.venv\Scripts\python.exe tools/mock_targets.py            # 127.0.0.1:2222, audituser / auditpass
.\.venv\Scripts\python.exe tools/ssh_client.py              # interactive client to show it is a real SSH server
```

One paramiko server answers the exact Linux, Cisco IOS XE and FortiGate reader commands. Its host key is `data/mock_ssh_host_rsa.key`. Use `--port` / `--host` to change the bind address. Live scans against it require `BG_LAB_TARGETS=true`.

## One-shot alternative

```powershell
powershell -File tools/dev.ps1 [-ApiPort 8000] [-WebPort 5173]
```

This seeds the database, starts the API (logs in `data/logs/`) if the port is free, runs `seed_demo.py --load`, then runs Vite in the foreground. It reuses healthy servers already running and never kills processes it did not start.

## Resetting

```powershell
docker compose -f deploy/compose/compose.yaml stop            # keep data
docker compose -f deploy/compose/compose.yaml down -v         # DESTROYS the database volume
```

After `down -v`, `seed_demo.py` creates a new org with a new random password and new TOTP secrets, and overwrites `data/demo-credentials.json`. Re-enroll authenticators, or use `tools/totp.py`. Pinned keys in `data/known_hosts` and the master key in `data/keys/` are kept.
