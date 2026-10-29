# Current HTTP API (development build)

The routes below are implemented in `apps/api/src/baselineguard_api/routes/v1`. Exact schemas are available from the development-only OpenAPI document when `BG_DOCS_ENABLED=true` and environment is not production. All routes are tenant-scoped; clients cannot select an organization header. Sessions use an HttpOnly cookie, and state-changing browser calls require the CSRF header/token contract. Mutations that create an object require a high-entropy `Idempotency-Key`; draft updates/publication use `If-Match` ETags.

## Routes present in source

| Method and path | Purpose | Important access rules |
|---|---|---|
| `GET /health/live` | Process liveness | No readiness/database guarantee |
| `GET /api/v1/me` | Current principal, site ids and CSRF token | Authenticated session |
| `POST /api/v1/auth/login` | Password phase, returns limited MFA challenge | Rate-limited; account/org status checked |
| `POST /api/v1/auth/verify` | TOTP or recovery code, create session cookie | Challenge-scoped; replay protected |
| `POST /api/v1/auth/logout` | Revoke current session | Authenticated + CSRF |
| `GET /api/v1/sites` | List visible sites | Inventory read roles + site filtering |
| `POST /api/v1/sites` | Create site scope | Platform administrator + idempotency |
| `GET /api/v1/assets` | List visible active assets | Site-filtered inventory read roles |
| `POST /api/v1/assets` | Register scoped asset | Inventory editor/platform administrator + scope check + idempotency |
| `POST /api/v1/assets/{id}/archive` | Archive an asset | Inventory editor/platform administrator |
| `POST /api/v1/scans` | Create scan request and target jobs | Scan operator, published policy and site-scoped assets |
| `GET /api/v1/scans` | List visible scan requests | Read role + site filtering |
| `GET /api/v1/scans/{id}` | Read a scan request | Read role + site filtering |
| `POST /api/v1/scans/{id}/cancel` | Cancel queued/running jobs | Scan operator + site scope |
| `GET /api/v1/packs` | List stored rule packs | Policy read role |
| `GET /api/v1/policies` | List visible policy revisions | Policy read role + site filtering |
| `GET /api/v1/policies/{id}` | Read a policy revision | Policy read role + ETag |
| `POST /api/v1/policy-drafts` | Create immutable revision draft | Policy author; approved pack required |
| `PATCH /api/v1/policy-drafts/{id}` | Update draft spec | Draft author, `If-Match` |
| `POST /api/v1/policy-drafts/{id}/publish` | Publish immutable draft | Separate policy approver, recent MFA, `If-Match`, idempotency |

## Deliberately absent workflows

This is not the full PRD API. Rule-pack ingestion/review, a completed worker pipeline, findings/evidence, exceptions/manual assessment, schedules, report export/download verification, credential and trust administration, remote collectors, integrations, audit query, user administration, backup/restore, and readiness/observability endpoints are incomplete. Do not infer routes from UI navigation labels. The next API acceptance work should add contract tests and authorization tests for every new route before exposing it to the GUI.

## Error handling and pagination

API errors use the shared error envelope with a request reference. List routes use bounded page sizes and signed, route/tenant-bound cursors. Clients should treat validation and authorization responses as terminal, and should use idempotency keys for safe mutation retries. Never put credentials, raw configuration, or session secrets in URLs or logs.
