# Repository map

See [overview](overview.md) for how the parts interact at runtime.

| Path | Contents | Notes |
|---|---|---|
| `apps/api` | FastAPI app `baselineguard_api`: `main.py` (app, middleware, error handlers), `config.py` (`BG_*` settings), `security.py` (sessions, CSRF, roles), `audit.py` (hash chain), `embedded.py` (in-process workers), `scheduling.py` (schedule tick), `bootstrap.py` (admin CLI), `routes/v1/*` | `python -m baselineguard_api` |
| `apps/collector` | `CollectorWorker` (claims `COLLECT` jobs, runs adapters, enforces trust) and `snapshot_store.py` (redact, normalize, encrypt, persist snapshot) | Runs only embedded in the API |
| `apps/evaluator` | `EvaluationWorker` and `persist.finalize` (result sets, control results, findings, run status) | Runs only embedded |
| `apps/reporter` | `render.py` (JSON/HTML/CSV with escaping, redaction and formula protection), `pdf.py` (dependency-free PDF) | Called by `POST /reports` |
| `apps/scheduler` | `schedule.py` (5-field cron, timezone/DST), `queue.py` (lease/retry/fencing primitives) | `queue.py` is used by tests, not by the embedded workers |
| `apps/web` | React 19 + Vite 8 + Tailwind 4 console and landing page (`src/pages/*`, `src/AuthPanel.tsx`, `src/lib/api.ts`), Vitest unit tests, Playwright `e2e/` | `pnpm --filter @baselineguard/web dev` |
| `packages/adapters` | `base/transport.py` (scope resolver, strict SSH), `linux/ssh.py`, `cisco_iosxe/reader.py`, `fortigate/reader.py`, `windows/reader.py`, `normalize.py`, `orchestrate.py` | Empty placeholder dirs: `checkpoint`, `cisco_asa`, `panos`, `sophos`, `fortigate`, `windows` (top level) |
| `packages/contracts` | Pydantic contracts (API, pipeline, policies, common fact/result types) | |
| `packages/credentials` | `envelope.py`: seal and unseal target credentials | |
| `packages/domain` | `scoring.py` (compliance summary), `network_acl.py` (static ACL analysis; not wired in) | |
| `packages/evidence` | `bundle.py`: encrypted content-addressed `ArtifactStore`, signing helpers | Tracked. `.gitignore` ignores only the root `/evidence/` and `/reports/` directories. |
| `packages/persistence` | `models.py` (SQLAlchemy), `database.py` (engine, tenant-scoped session) | See [data model](data-model.md) |
| `packages/rule_engine` | `packs.py` (safe loading + schema), `canonical.py` (canonical JSON, digests), `resolve.py` (policy overrides/exclusions), `evaluator.py`, `logic.py` (three-valued logic) | |
| `packages/network_analysis` | Empty placeholder | |
| `content/original` | Four rule packs (103 controls) | [Content provenance](../content-provenance/README.md) |
| `content/remediation` | Remediation catalogs, one per pack | |
| `content/schemas` | `rule-pack.schema.json` | |
| `content/compatibility.yaml` | Planned platform matrix (all `planned`) | |
| `migrations` | Alembic `env.py` and revisions `0001`–`0006` | Uses `BG_MIGRATION_DATABASE_URL` |
| `tools` | `seed_demo.py`, `sync_demo.py`, `mock_targets.py`, `ssh_client.py`, `totp.py`, `audit_local_machine.py`, `build_rule_packs.py`, `dev.ps1`, `ubuntu_lab_setup.sh`, `check_ubuntu_target.py` | Development and demo utilities |
| `tests` | `unit/`, `integration/` (need DB URLs); empty `contracts/`, `fixtures/`, `performance/`, `properties/`, `security/` placeholders | `uv run pytest` |
| `deploy/compose` | Dev PostgreSQL 17 on `127.0.0.1:55432` + role init script | |
| `deploy/containers` | `Dockerfile.api`, `Dockerfile.web`, `nginx.conf` | Not exercised by CI |
| `deploy/helm`, `deploy/monitoring`, `deploy/offline` | Empty placeholders | |
| `readers/`, `templates/` | Placeholder directories (`templates/reports` is tracked) | |
| `data/` (git-ignored) | Master key, evidence store, known_hosts, demo credentials, mock host key, logs | Created at runtime |
| `docs/` | This documentation | [Index](../README.md) |
| `USER_MANUAL.md`, `PRD.md` | Presenter manual; original product requirements | The PRD describes the full target product, not the current build |
