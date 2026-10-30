# Project status

Status as of 2026-10-30, branch `demo-ready`. This file replaces the earlier phase-gate record. It describes what the code actually does today.

## Working end to end

| Capability | State | Where |
|---|---|---|
| Local sign-in with password + TOTP MFA, recovery codes, rate limiting, revocable sessions, CSRF | Working | `routes/v1/auth.py`, `security.py` |
| Demo sign-in (password only) and "Auto-fill demo code" | Working when `BG_DEMO_LOGIN=true`; refused in production | `auth.py`, `AuthPanel.tsx` |
| Multi-tenancy with forced Postgres RLS, site-scoped role bindings | Working; covered by integration tests | migrations, `tests/integration/test_postgres_tenant_rls.py` |
| Sites with CIDR/port/DNS allow-lists | Working. The "New site" form is on the Assets page (platform_admin). | `inventory.py`, `Assets.tsx` |
| Asset register, archive and CSV bulk import (preview + commit) | Working | `inventory.py` |
| **Live Windows local audit** (`windows-local`) of the machine running the API | Working. Some secedit/auditpol controls are `UNKNOWN` unless the API runs elevated. | `windows/reader.py`, `tools/audit_local_machine.py` |
| **Live SSH collection pipeline**: host-key read, compare, pin, sealed credential, scoped connect, fixed readers, normalize, encrypted snapshot, evaluate | Working against the mock devices and real SSH servers | `live.py`, `collector/worker.py`, `adapters/*` |
| Mock SSH lab devices (Ubuntu 22.04, Cisco Catalyst 9300 IOS XE 17.12, FortiGate 100F 7.4) on `127.0.0.1:2222` | Working (`BG_LAB_TARGETS=true`) | `tools/mock_targets.py`, `tools/sync_demo.py` |
| Real Ubuntu onboarding: setup script, preflight, `sudo -n sshd -T` fallback | Added; see the [runbook](../runbooks/ubuntu-lab-onboarding.md) | `tools/ubuntu_lab_setup.sh`, `tools/check_ubuntu_target.py` |
| Fixture/sample assets via offline import (`/imports/sample` → `/imports`) | Working; labeled `source=import` | `pipeline.py` |
| Deterministic evaluation of 103 original controls across 4 packs; snapshot, engine and semantic digests | Working | `evaluator/`, `rule_engine/` |
| Findings lifecycle (open/resolve/reopen, owner, due date, comments) | Working. Manual review is API-only. | `persist.py`, `pipeline.py` |
| Exceptions with dual custody (requester ≠ approver, expiry, revoke) | Working | `pipeline.py` |
| Reports: JSON, HTML, CSV, PDF; encrypted, hash-checked and audited downloads | Working (rendered synchronously) | `pipeline.py`, `apps/reporter` |
| Policy catalog, draft/edit/publish with independent approver, impact preview | Working (API and UI) | `policies.py`, `Policies.tsx`, `PolicyEditor.tsx` |
| Cron schedules (timezone/DST aware, idempotent occurrences) for non-fixture assets | Working inside embedded workers | `scheduling.py`, `apps/scheduler` |
| Drift between the two newest result sets | API only (no UI caller) | `GET /assets/{id}/drift` |
| Audit hash chain (append-only, per-org sequence) | Written on every security action; no verifier | `audit.py` |
| Landing page, in-app docs page, dark/light theme, command palette | Working | `apps/web` |

## Known limitations and defects

These were found while writing these docs, from the code as of this date.

| # | Issue | Impact |
|---|---|---|
| 1 | No lease-expiry recovery in the embedded workers. | A crash mid-job leaves the job `RUNNING`. |
| 2 | `POST /api/v1/collector/snapshots` constructs `Snapshot(collector_id=..., normalized_envelope=...)`. Those columns do not exist, and the route omits required columns (`digest`, `observed_*`, `received_at`). | The external-collector upload route fails. The embedded workers do not use it. |
| 3 | `POST /assets/import-commit` does not re-validate site visibility or the CIDR scope (preview checks ports only). | CSV-imported assets can sit outside their site's CIDRs. Collection still enforces scope. |
| 4 | `GET /api/v1/assessments` is not site-filtered. | Site-scoped users see run and asset names of other sites in the org. |
| 5 | Demo-login sessions set `mfa_verified_at`. | They satisfy the "recent MFA" check for policy publication. |
| 6 | `schedules.overlap_policy` is stored but not enforced. | A slow run can overlap the next occurrence. |
| 7 | `windows-local` ignores the asset address. | It always audits the collector host. Two `windows-local` assets audit the same machine. |
| 8 | The Connect sheet accepts only a password; the API also accepts `private_key_pem`. | Key-only Ubuntu hosts need a password allowed for the audit user (see the runbook), or an API call. |
| 9 | The fixture adapters need a `fixture_root` that the embedded worker does not set. | Scanning a `*-fixture` asset fails with `FIXTURE_ROOT_NOT_CONFIGURED`. Fixture assets are populated by offline import instead. |
| 10 | No API or tool verifies the audit hash chain. | Integrity is enforced by triggers, but there is no verifier. |
| 11 | `packages/domain/network_acl.py` (static ACL analysis) is tested but not wired into evaluation. | — |
| 12 | `content/compatibility.yaml` still lists every platform as `planned`. No vendor-lab certification exists. | Claims are limited to the mock devices and machines you test yourself. |

### Fixed on 2026-10-30

- `.gitignore` now uses root-anchored `/evidence/` and `/reports/`, so `packages/evidence/` and `templates/reports/` are tracked.
- The collector now also claims `RETRY_WAIT` jobs once `available_at` has passed. Backoff is `10 × 2^attempt` s (20 s, then 40 s). After 3 attempts the target fails closed with `ERROR` results, so retryable SSH errors no longer hang a scan.
- `tools/seed_demo.py` uses the categories `switch` and `router`, so seeding a new database works.
- `.env.example` documents `BG_EMBEDDED_WORKERS=true` and `BG_WORKER_DATABASE_URL`.
- `POST /collector/jobs/{id}/fail` now requires `scan_operator` or `platform_admin`.
- The UI (Assets, Assessments) and `sync_demo.py` now treat `CANCELLED` as terminal.
- CSV import changes:
  - Categories now match the database (`network` is accepted as an alias for `switch`).
  - Each category has a default adapter.
  - `tags` is sent as an object.
  - The preview lists each invalid row's errors.
  - "Insert sample" now produces 3 valid rows.
- The `sshd` value `permitrootlogin without-password` is normalized to `prohibit-password`. A stock Ubuntu host now gives a real FAIL on the root-login control instead of UNKNOWN.
- The Linux reader no longer aborts when a command writes to stderr. Each command's stdout and exit code are kept, and unreadable facts become unavailable.
- Smaller UI changes:
  - Exception toasts now say approved, rejected or revoked.
  - API errors name the offending fields.
  - The Assets page shows load errors.
  - The Docs page says "Continue".
- The Playwright spec moved to `apps/web/e2e/`.

## Not implemented

- Remote WinRM collection.
- Readers for RHEL, Cisco ASA, PAN-OS, Check Point and Sophos (empty `packages/adapters/*` placeholders).
- SSO/OIDC.
- Remote collector agents (beyond the partial API).
- A rule-pack upload/approval workflow (packs are registered by the seed tools).
- User administration UI.
- Production deployment: `deploy/containers` has Dockerfiles; `deploy/helm`, `deploy/monitoring` and `deploy/offline` are empty.
- Backup/restore.
- CIS-licensed content: all packs are original organizational content (see [content provenance](../content-provenance/README.md)).
