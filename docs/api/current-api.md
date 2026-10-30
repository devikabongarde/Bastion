# HTTP API reference

This page lists every route registered by `apps/api/src/baselineguard_api/routes/health.py` and `routes/v1/*.py`, all under the `/api/v1` prefix. When `BG_DOCS_ENABLED=true` and `BG_ENVIRONMENT` is not `production`, the API also serves an OpenAPI document at `/api/openapi.json` and Swagger UI at `/api/docs`.

## Conventions

- **Authentication.** Every `/api/v1` route except `auth/login`, `auth/mfa/verify`, `auth/options`, `auth/demo-code` and `auth/demo-login` needs a valid session cookie (`__Host-bg_session`). Requests without one get `401 AUTHENTICATION_REQUIRED`.
- **Tenant.** The organization always comes from the session. Each request runs in a transaction with `app.org_id` set, and row-level security applies.
- **CSRF.** Every non-`GET`/`HEAD`/`OPTIONS` request needs an `X-CSRF-Token` header. Its value comes from `/auth/mfa/verify`, `/auth/demo-login` or `GET /me`. Requests without it get `403 CSRF_REJECTED`.
- **Idempotency.** `POST /sites`, `POST /assets`, `POST /scans`, `POST /policy-drafts` and `POST /policy-drafts/{id}/publish` require an `Idempotency-Key` header of 16–200 characters. A replay with the same key and body returns the saved response. The web client sends a random UUID on every write.
- **Optimistic concurrency.** `PATCH /policy-drafts/{id}` and `POST /policy-drafts/{id}/publish` require `If-Match: <ETag>`. A stale value gets `409 STALE_VERSION`.
- **Errors.** Errors are JSON problem documents: `{type, title, status, code, detail, request_id, errors?}`. Every response carries `X-Request-ID`, `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY` and `Referrer-Policy: no-referrer`.
- **Pagination.** `GET /sites`, `/assets`, `/scans`, `/packs` and `/policies` return `{items, next_cursor}`. They accept `limit` (1–200, default 50) and an opaque signed `cursor` bound to the route and tenant. Other list routes return `{items}` with fixed limits.
- **Roles.** "Any role" means any of: viewer, analyst, scan_operator, auditor, platform_admin, risk_approver, manual_assessor, inventory_editor, policy_author, policy_approver. Site-scoped bindings further limit which sites' objects are visible. Role checks are evaluated against the caller's role set.

## Health (no prefix, not in OpenAPI)

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/health/live` | none | Process liveness: `{"status": "live"}` |
| GET | `/health/ready` | none | Runs `SELECT 1`; returns 503 `not_ready` if the database is unreachable |

## Identity: `routes/v1/auth.py` and `router.py`

| Method | Path | Required role | Purpose |
|---|---|---|---|
| GET | `/api/v1/me` | authenticated | User id, org id, roles, site ids and CSRF token |
| POST | `/api/v1/auth/login` | none (rate-limited) | `{organization, username, password}`. On success returns `202 {challenge, next_step: "mfa", expires_in_seconds: "300"}`. Any failure returns `401 INVALID_CREDENTIALS`. |
| POST | `/api/v1/auth/mfa/verify` | none (challenge) | `{challenge, code}` or `{challenge, recovery_code}`. Sets the session cookie and returns `{status, csrf_token}`. A challenge allows 5 attempts. |
| GET | `/api/v1/auth/options` | none | `{demo_login: bool}`. The sign-in page uses it to show "Quick demo access". |
| POST | `/api/v1/auth/demo-code` | none; only when `BG_DEMO_LOGIN=true` (404 otherwise) | Returns the current TOTP code for a pending, password-verified challenge. The UI uses it for "Auto-fill demo code". |
| POST | `/api/v1/auth/demo-login` | none; only when `BG_DEMO_LOGIN=true` (404 otherwise) | Password-only sign-in. The audit event records `factor: demo-password-only`. |
| POST | `/api/v1/auth/logout` | authenticated | Revokes the session and clears the cookie (204) |

## Inventory: `routes/v1/inventory.py`

| Method | Path | Required role | Purpose |
|---|---|---|---|
| GET | `/api/v1/sites` | viewer, analyst, scan_operator, auditor, inventory_editor, platform_admin | List visible sites (cursor page) |
| POST | `/api/v1/sites` | platform_admin | Create a site `{name, timezone, scope: {allowed_cidrs (≥1, no /0), allowed_ports (≥1), allowed_dns_suffixes}}`. Needs `Idempotency-Key`. |
| GET | `/api/v1/assets` | same as `GET /sites` | List active assets. Filters: `category` (windows/linux/firewall/router/switch) and `site_id`. Each asset includes `collection_mode`, `host_key_fingerprint`, `host_key_verified_at` and `credential_bound`. |
| POST | `/api/v1/assets` | inventory_editor, platform_admin | Register an asset. The address must be an IP inside `allowed_cidrs` or a name under `allowed_dns_suffixes`, and the port must be in `allowed_ports`; otherwise `422 ASSET_OUTSIDE_SITE_SCOPE`. A duplicate endpoint gives `409 ASSET_ALREADY_EXISTS`. Needs `Idempotency-Key`. |
| POST | `/api/v1/assets/{asset_id}/archive` | inventory_editor, platform_admin | Archive (soft-delete) an asset (204) |
| POST | `/api/v1/assets/import-preview` | inventory_editor, platform_admin | Validate CSV text. `name` and `address` are required. Optional columns: `port` (default 22), `category`, `criticality`, `role`/`declared_role`, `adapter`/`adapter_id`, `site`/`site_name`/`site_id`. Categories are windows/linux/firewall/router/switch; `network` is accepted as an alias for `switch`. Default adapter by category: windows → `windows-local`, router/switch → `cisco-iosxe`, firewall → `fortigate-ssh`, otherwise `linux-ssh`. The preview checks ports against the site and duplicates in the batch and the database, and returns per-row errors. |
| POST | `/api/v1/assets/import-commit` | inventory_editor, platform_admin | Insert the previewed rows (`tags` is an object). Note: this route does **not** re-check site visibility or the CIDR scope. |

## Live onboarding: `routes/v1/live.py`

| Method | Path | Required role | Purpose |
|---|---|---|---|
| POST | `/api/v1/assets/{asset_id}/host-key` | platform_admin, credential_admin | Live-SSH assets only (`linux-ssh`, `cisco-iosxe`, `fortigate-ssh`; otherwise `422 NOT_A_LIVE_SSH_ASSET`). Scope-checks the endpoint, opens an SSH transport, and returns `{key_type, fingerprint}` (`SHA256:<base64>`). Nothing is stored. Errors: `422 TARGET_*`, `502 TARGET_UNREACHABLE`. |
| POST | `/api/v1/assets/{asset_id}/connect` | platform_admin, credential_admin | `{username, fingerprint, password` **or** `private_key_pem}`. Re-reads the key; if it differs from `fingerprint`, returns `409 HOST_KEY_CHANGED`. Otherwise it pins the key in `BG_KNOWN_HOSTS_FILE`, revokes the old `asset_trust` row and writes a new one, seals the credential and binds it (`audit_collect`). |

## Scans: `routes/v1/scans.py`

| Method | Path | Required role | Purpose |
|---|---|---|---|
| POST | `/api/v1/scans` | **scan_operator** (`platform_admin` alone is not enough) | `{asset_ids, policy_revision_id, reason}`. The policy must be published and its packs approved with unchanged digests (`409 POLICY_CONTENT_UNAVAILABLE`). Assets must be in the caller's sites and in the policy's `site_ids` (`422 POLICY_SCOPE_MISMATCH`). Creates the run, targets and `COLLECT` jobs; returns 202. Needs `Idempotency-Key`. |
| GET | `/api/v1/scans` | viewer, analyst, scan_operator, auditor, platform_admin | List runs (cursor page). A run that touches a hidden site is omitted. |
| GET | `/api/v1/scans/{scan_id}` | same as `GET /scans` | Run status and target count |
| POST | `/api/v1/scans/{scan_id}/cancel` | scan_operator | Cancels pending/running jobs and targets. A terminal run gives `409 SCAN_NOT_CANCELLABLE`. |

## Collector protocol: `routes/v1/collector.py`

These routes are for an out-of-process collector agent. The embedded workers do not use them. See [project status](../development/project-status.md#known-limitations-and-defects) for known defects.

| Method | Path | Required role | Purpose |
|---|---|---|---|
| POST | `/api/v1/collector/jobs/claim` | scan_operator, platform_admin | `{site_id, collector_id?, supported_adapters?}`. Claims the next `QUEUED` `COLLECT` job for the site with a 5-minute lease. Returns target details or nulls. |
| POST | `/api/v1/collector/snapshots` | scan_operator, platform_admin | Upload facts for a leased job (`409 LEASE_EXPIRED` if the lease was lost) and enqueue `EVALUATE` |
| POST | `/api/v1/collector/jobs/{job_id}/fail?reason=...` | scan_operator, platform_admin | Sets the job to `DEAD_LETTER` with `error_code = reason[:64]` and clears its lease. Marks the target `FAILED` with the same `error_code` and a `finished_at`. |

## Assessment pipeline: `routes/v1/pipeline.py`

| Method | Path | Required role | Purpose |
|---|---|---|---|
| GET | `/api/v1/overview` | any role | Dashboard data: per-asset posture from the latest result sets, compliance, finding counts, freshness |
| GET | `/api/v1/findings` | any role | Filters: `state` (OPEN/RESOLVED/RISK_ACCEPTED), `severity`, `asset_id`, `q`, `limit` ≤200 |
| GET | `/api/v1/findings/{finding_id}` | any role | Finding detail: result, expected/actual values, evidence pointers, remediation template, history |
| PATCH | `/api/v1/findings/{finding_id}` | analyst, scan_operator, platform_admin | Set `owner_id`, `due_at` or add a `comment` (writes finding events and audit) |
| POST | `/api/v1/findings/{finding_id}/review` | manual_assessor, platform_admin | Record a manual review (`CONFIRMED_PASS` / `CONFIRMED_FAIL` / `REJECTED_ASSESSMENT`, future `expires_at`). It does not change the engine result. |
| GET | `/api/v1/users` | any role | Active users of the organization (id, email), for assignment |
| GET | `/api/v1/imports/sample` | any role | Generate a sample import bundle. Parameters: `profile` (hardened/mixed/weak), `variant` 0–2, `family` (ubuntu/windows_server/cisco_ios_xe/fortigate), `role` (router/switch). |
| POST | `/api/v1/imports` | scan_operator, platform_admin | Offline import of normalized facts (`ImportBundle` + `policy_revision_id`). Float values are rejected (`422 FLOAT_FACT`). Creates a `source='import'` snapshot, run and target, and enqueues `EVALUATE`. |
| GET | `/api/v1/assessments` | any role | The latest 50 runs with per-target state, compliance %, failed count and result digest. Not site-filtered. |
| GET | `/api/v1/assessments/{run_id}` | any role | One run in full: per target the state, error code, compliance %, summary, semantic and engine digests, and every top-level control verdict (`control_key`, `title`, `severity`, `status`, `reason_code`, `expected`, `actual`), failures first. Powers the run panel on Assessments. |
| GET | `/api/v1/exceptions` | any role | Exceptions with effective state (`EXPIRED` is computed) |
| POST | `/api/v1/exceptions` | analyst, scan_operator, platform_admin | Request an exception `{asset_id, control_key, reason, compensating_controls, expires_at}`. A finding must exist (`422 NO_MATCHING_FINDING`). |
| POST | `/api/v1/exceptions/{exception_id}/approve` | risk_approver, not the requester (`403 SELF_APPROVAL_DENIED`) | Approve a `REQUESTED` exception. Open findings for that control become `RISK_ACCEPTED`. |
| POST | `/api/v1/exceptions/{exception_id}/reject` | risk_approver, not the requester | Reject a `REQUESTED` exception |
| POST | `/api/v1/exceptions/{exception_id}/revoke` | risk_approver, platform_admin | Revoke an `APPROVED` exception. Risk-accepted findings reopen. |
| GET | `/api/v1/reports` | any role | List reports |
| POST | `/api/v1/reports` | auditor, analyst, platform_admin | `{format: json\|html\|csv\|pdf, asset_ids?, run_id?, policy_revision_id?, evidence_level?}`. Renders the latest result set per visible asset synchronously and stores an encrypted artifact. Returns `409 NO_RESULTS` if nothing has been assessed. |
| GET | `/api/v1/reports/{report_id}/download` | auditor, analyst, platform_admin, viewer | Downloads the artifact, checking its stored SHA-256, and writes an audit event |
| GET | `/api/v1/policy-overview` | any role | Policy catalog for the Policies page: policy revisions (state, digest), plus every control with its pack, severity, origin, rationale, whether a remediation template exists, and result counts by status |

## Policies: `routes/v1/policies.py`

| Method | Path | Required role | Purpose |
|---|---|---|---|
| GET | `/api/v1/packs` | viewer, analyst, scan_operator, auditor, policy_author, policy_approver, platform_admin | List stored rule packs (cursor page) |
| GET | `/api/v1/policies` | same as `/packs` | List policy revisions visible to the caller's sites (cursor page) |
| GET | `/api/v1/policies/{policy_id}` | same as `/packs` | Read a revision; returns an `ETag` header |
| POST | `/api/v1/policy-drafts` | policy_author | Create a draft from approved packs and a spec. Validation errors: `CONTROL_ID_CONFLICT`, `UNKNOWN_CONTROL`, `EMPTY_POLICY`, `INVALID_THRESHOLD_TYPE`. Needs `Idempotency-Key`. |
| PATCH | `/api/v1/policy-drafts/{policy_id}` | policy_author, and only the draft's author (`DRAFT_AUTHOR_REQUIRED`) | Update the draft spec. Needs `If-Match`. |
| POST | `/api/v1/policy-drafts/{policy_id}/publish` | policy_approver, MFA within the last 5 minutes, not the author (`INDEPENDENT_APPROVAL_REQUIRED`) | Publish the draft (it becomes immutable). Needs `If-Match` and `Idempotency-Key`. |
| GET | `/api/v1/policy-drafts/{policy_id}/impact` | same as `/packs` | Preview the draft against each in-scope asset's latest snapshot: projected status per control and changes from the current results |

## Schedules and drift: `routes/v1/schedules.py`

| Method | Path | Required role | Purpose |
|---|---|---|---|
| GET | `/api/v1/schedules` | any role | Schedules with last and next occurrence, plus the site list |
| POST | `/api/v1/schedules` | scan_operator, platform_admin | `{name, site_id, policy_id, cron, timezone, overlap_policy}`. The cron and timezone are validated (`422 INVALID_SCHEDULE`). The policy must be published. |
| POST | `/api/v1/schedules/{schedule_id}/toggle` | scan_operator, platform_admin | Enable or disable a schedule |
| GET | `/api/v1/assets/{asset_id}/drift` | any role | Control status changes between the asset's two newest result sets. Flags whether the two used different policies. |

Scheduled runs include only the site's non-fixture assets. The schedule tick runs every 30 s inside the embedded workers.
