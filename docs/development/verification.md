# Verification: how to run every check

Run all commands from the repository root. They assume the `uv` workspace is installed (`uv sync --all-packages --group dev`) and that web dependencies are installed (`corepack pnpm install --frozen-lockfile`). See [local setup](local-setup.md).

## Python

| Check | Command | Scope |
|---|---|---|
| Lint | `uv run ruff check apps packages tests migrations tools` | Ruff rules E, F, I, B, UP, S, ASYNC; line length 100. Per-file ignores are in `pyproject.toml`. CI lints `apps packages tests migrations` (no `tools`). |
| Types | `uv run pyright` | `pyrightconfig.json`, basic mode. Covers apps/api, collector, reporter, scheduler, packages adapters/contracts/domain/persistence/rule_engine, and migrations. The evaluator, evidence and credentials packages are not in its include list. |
| Unit tests | `uv run pytest -m "not integration and not live"` | `tests/unit`: rule engine, adapters (Linux reader, Cisco switch, FortiGate, Windows), collector scope, CSV import, API security/contracts, reporter, scheduling, identity, network ACL. |
| All tests | `uv run pytest` | Adds `tests/integration` (job queue including the collector fail endpoint, local auth, tenant RLS, CSV import). These tests **skip** unless the database URLs are set. |
| Migration state | `uv run alembic current` | Expect `0006_live_onboarding_grants (head)` |

Pytest settings come from `[tool.pytest.ini_options]`: `testpaths = ["tests"]`, `--strict-markers --strict-config`, and the markers `integration` and `live`.

### Integration tests

Set both URLs for the current shell. Use the values from your `.env`, never copied into files.

```powershell
$env:BG_MIGRATION_DATABASE_URL = "postgresql+psycopg://bg_migration:<password>@127.0.0.1:55432/baselineguard"
$env:BG_DATABASE_URL           = "postgresql+psycopg://bg_api:<password>@127.0.0.1:55432/baselineguard"
uv run pytest -m integration
```

The database must be at migration head. The tests create and clean up their own organizations.

### Windows temp-directory tip

On Windows, pytest's default base temp directory (`%TEMP%\pytest-of-<user>`) is sometimes not writable or accessible, for example under managed or sandboxed profiles. The symptom is `PermissionError` while setting up `tmp_path`. Point pytest at a directory inside the repo instead (`test-results/` is git-ignored):

```powershell
uv run pytest --basetemp=./test-results/pytmp
```

## Web (`apps/web`)

| Check | Command | Notes |
|---|---|---|
| Type check | `corepack pnpm --filter @baselineguard/web typecheck` | `tsc -b --pretty false` |
| Unit tests | `corepack pnpm --filter @baselineguard/web test` | Vitest (jsdom), `src/**/*.test.{ts,tsx}` (`lib/status.test.ts`, `lib/bastion.test.ts`) |
| Production build | `corepack pnpm --filter @baselineguard/web build` | `tsc -b && vite build` → `apps/web/dist` |
| Browser E2E | `corepack pnpm --filter @baselineguard/web test:e2e` | Playwright, `apps/web/e2e/*.spec.ts`, Chromium. The config starts `npm run dev` on `127.0.0.1:5173`, or reuses a running server outside CI. The tests stub `/health/live` and `/api/v1/me` with `page.route`, so no API is needed. First time only: `corepack pnpm --filter @baselineguard/web exec playwright install chromium`. |

The root `package.json` has shortcuts: `pnpm typecheck | test | build | test:e2e`.

## Manual / live checks

- **Manual UI test plan:** [../testing/ui-test-guide.md](../testing/ui-test-guide.md)
- **Local Windows audit, no database needed:** `.\.venv\Scripts\python.exe tools/audit_local_machine.py`
- **End-to-end live scan against the mock lab devices:** start `tools/mock_targets.py`, then run `tools/sync_demo.py --load`. It prints `live scan finished: COMPLETED|PARTIAL`.
- **Real Ubuntu host preflight:** `.\.venv\Scripts\python.exe tools/check_ubuntu_target.py <ip> --user audituser`. See the [runbook](../runbooks/ubuntu-lab-onboarding.md).

## CI (`.github/workflows/ci.yml`)

One job, `python`, runs on `ubuntu-latest` on every push and pull request. It starts a `postgres:17-alpine` service and then:

1. Sets up Python 3.12 and Node 24, installs `uv` and enables pnpm through corepack.
2. Runs `uv sync --locked --all-packages --group dev` and `pnpm install --frozen-lockfile`.
3. Creates the `bg_migration` and `bg_api` roles (`NOBYPASSRLS`) with `psql`. These are the same grants as the Compose init script.
4. Runs `ruff check apps packages tests migrations`, `pyright` and `pnpm typecheck`.
5. Runs `alembic upgrade head` with the migration role.
6. Runs `pytest` with both DB URLs set, so integration tests run, then `pnpm test` and `pnpm build`.
7. Rehearses migration rollback: `alembic downgrade base` followed by `alembic upgrade head`.
8. Runs `playwright install --with-deps chromium` and `pnpm test:e2e`.


## Not covered by these checks

- Live collection against vendor hardware or specific firmware builds.
- Performance at scale.
- Backup and restore.
- Container images and Helm. `deploy/containers` has Dockerfiles; `deploy/helm` is empty.
- An independent security review.
