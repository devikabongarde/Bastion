# Phase 1 threat model baseline

**Status:** Initial engineering draft; security review is an open Phase 0 gate.

## Assets and trust boundaries

- Target credentials, session and signing keys, collector identities, raw evidence, normalized facts, policy packs, scan results, tenant data, and the append-only audit chain.
- Browser to API; API to PostgreSQL; collector to managed device; collector upload to API; parser/evaluator/report worker to untrusted device output; administrator to rule-pack import.
- The API and database are not directly reachable from site networks. Remote collectors will use outbound mTLS only when the Phase 2 protocol is implemented.

## Threats and current controls

| Threat | Phase 1 control | Remaining verification |
|---|---|---|
| Cross-tenant reads or writes | Transaction-local organization ID, forced PostgreSQL RLS, composite tenant foreign keys, API site filters | Integration test two organizations using `bg_api` after PostgreSQL is available |
| SSRF or DNS rebinding | Explicit site CIDR/DNS-suffix/port scope, every DNS answer authorized, one resolved IP pinned to the socket | Adversarial resolver/transport tests and live lab test |
| SSH MITM or credential downgrade | Explicit known-hosts file and reject-on-miss; key and password are mutually exclusive; pinned IP socket with original host key name | Device host-key fixture and authorized lab test |
| Malicious rule pack | Safe YAML loader, duplicate-key rejection, byte/depth/node bounds, no runtime code, JSON Schema validation | Property/fuzz coverage and resource-limit tests |
| Secret leakage in device configuration | Cisco secret and certificate-line redaction before persistence; logging omits config payloads | Expand secret corpus and parser-aware tests for every adapter |
| Mutable published policy or audit history | Database trigger blocks published policy edits; audit rows are append-only with hash chaining | Trigger behavior and chain verification integration tests |
| Browser/API information leakage | Same-origin default, CSP/security headers, request IDs, sanitized problem responses, no local storage for credentials | Authentication/CSRF/MFA controls arrive in Phase 2 |
| Unavailable or partial device evidence shown as compliant | Explicit PASS/FAIL/UNKNOWN/NOT_APPLICABLE/ERROR statuses; collection errors are not passes | Full collector completeness contracts and end-to-end result pipeline remain open |

## Privilege and data handling assumptions

- Collectors have read-only target accounts and receive one credential at a time; no writer credential is part of the audit collector.
- Device output is untrusted input. Size limits and parsing isolation must be enforced before future evidence/report processing.
- Runtime database identity is a distinct `NOBYPASSRLS`, non-owner role. Migrations use a separate owner role. Tenant context is transaction-local to prevent pooled-connection leakage.
- The Phase 1 schema stores evidence hashes and typed result data foundations; encrypted evidence storage, collector signatures, credential brokering, and formal retention workflows are not yet implemented.
- No raw benchmark text or CIS mapping is included. Original rule content remains labeled organizational until rights review approves any mapping.

## Release-blocking review items

1. Security reviewer signs off on tenant context, database role grants, SSRF controls, host key handling, parser limits, and audit integrity.
2. Run adversarial cross-tenant and collector-scope tests against PostgreSQL using the runtime role.
3. Complete the synthetic secret corpus and tampered-bundle tests before claiming the Phase 1 evidence acceptance criterion.
4. Record exact authorized Ubuntu and IOS XE lab builds and exercise the read-only adapters; no fixture result substitutes for this evidence.
