# Implementation status against PRD Section 21

Status date: 2026-10-29. This is a repository inspection record, not a completion claim. A task is complete only when its Section 21 acceptance criteria are evidenced. Fixture tests do not satisfy live-device gates.

## Phase 0 — Scope and proof of feasibility

| Task | Status | Evidence / missing gate |
|---|---|---|
| P0-01 platform/build/role matrix and labs | Blocked | Planned rows are in `content/compatibility.yaml`; no authorized vendor lab/build owner is recorded. |
| P0-02 content rights/provenance | Incomplete | Provenance policy and original-content declaration exist; legal/right-to-distribute clearance and exact CIS sources do not. |
| P0-03 threat model/schema/protocol ADRs | Incomplete | Threat model and three ADRs exist; no complete review sign-off for every trust boundary/data contract. |
| P0-04 WinRM/JEA, IOS XE, FortiGate spikes | Blocked | SSH reader code and IOS XE reader code exist; Windows/FortiGate spikes and authorized live tests are absent. |
| P0-05 UX validation | Incomplete | GUI exists and browser navigation tests pass; no five-user validation evidence. |

**G0: Not passed.** Do not claim platform feasibility or CIS content distribution rights.

## Phase 1 — Core vertical slice

| Task | Status | Evidence / missing gate |
|---|---|---|
| P1-01 repository/CI/schema/migrations | Incomplete | Repository, CI configuration, migrations and contracts exist; local PostgreSQL is at migration head and tests pass; rollback rehearsal and complete contracts are absent. |
| P1-02 evidence envelope/storage/redaction/signatures | Incomplete | TOTP secret envelope encryption, IOS XE line redaction and tests exist; immutable signed evidence bundle, storage lifecycle and tamper-rejection pipeline are absent. |
| P1-03 Linux + IOS XE vertical adapters | Incomplete | Fixed readers and transport safety code exist; no complete normalized evidence contract or authorized live collection. |
| P1-04 DSL/status/scoring/20 rules/replay | Complete as an isolated engine task | The original pack has 20 organizational controls; every control has pass/fail/unknown/not-applicable fixtures; collection error is tested as `ERROR`; a deterministic 100-replay check passes. It is not yet connected to a persisted collection/evaluation pipeline and does not claim CIS coverage. |
| P1-05 asset/scan/finding UI + JSON/HTML export | Incomplete | Asset listing and scan request screens exist; workers/findings/report exports are not end to end. |

**G1: Not passed.** Current browser E2E validates shell/navigation using synthetic responses only.

## Phase 2 — MVP coverage and operations

| Task | Status | Evidence / missing gate |
|---|---|---|
| P2-01 Windows collection | Not implemented | No Windows reader or live/permission/localization fixtures. |
| P2-02 FortiGate and IOS XE switch | Incomplete | IOS XE reader component exists; FortiGate absent and switch intent evidence/live validation absent. |
| P2-03 minimum rules and static ACL analyzer | Incomplete | Static ACL analysis library has tests; it is not wired to normalized vendor evidence and platform minimum rule counts are unmet. |
| P2-04 policy draft/publish/preview/provenance | Incomplete | Draft create/edit, two-person publish, digest validation and coverage summary exist; preview/diff, usable pack ingestion/approval and full content provenance workflow are absent. |
| P2-05 durable queue/schedules/leases/cancellation | Incomplete | PostgreSQL queue lease/retry/fencing/cancellation primitives and integration tests exist; a bounded cron evaluator now has timezone, nonexistent-time and repeated-time DST unit tests. Durable schedule rows, occurrence locking/deduplication, blackout/scan windows and worker processing remain absent. |
| P2-06 RBAC/MFA/secrets/trust/audit | Incomplete | Local password/TOTP, recovery, role/site checks, encrypted TOTP secret and hash-chained audit events exist; credential/trust management, complete authorization review and audited exports are absent. |

**G2: Not passed.** Required live paths and complete rules/security gates are not present.

## Phase 3 — Pilot-ready release

| Task | Status | Evidence / missing gate |
|---|---|---|
| P3-01 dashboard/findings/exceptions/manual reviews | Not implemented | No persisted result/findings lifecycle or exception/manual review workflows. Dashboard deliberately displays no fabricated score. |
| P3-02 four export formats + verification bundle | Incomplete | Frozen report contract plus deterministic JSON, HTML and CSV renderers now exist with escaping, secret redaction, formula protection and per-artifact hashes. PDF rendering, report job/API integration, signature/ZIP verification bundle, access reauthorization and parity/security/visual gates remain absent. |
| P3-03 remediation plans | Incomplete | Example rule remediation identifiers exist; no reviewed, versioned, tested remediation catalog or complete failure coverage. |
| P3-04 500-asset performance/security/offline/restore | Not run | No benchmark, restore drill or independent security review. |
| P3-05 pilot users/sites/operational docs | Not run | No pilot organizations or 100 authorized assets. |

**G3: Not passed.**

## Phases 4 and 5

- **Phase 4:** Windows/extended Linux and firewall adapters, full rule inventories, remote collectors, OIDC and integrations are unimplemented or unverified. **G4 not passed.**
- **Phase 5:** HA deployment, 10,000-asset load/network impact, independent security review, content updates/deprecation, backup/recovery and operator handover are not implemented or tested. Deployment remains intentionally deferred as requested. **G5 not passed.**

## Completed work in the current continuation

- Corrected README setup/scope statements and created actual first-run, API, architecture/repository, adapter compatibility and content provenance documentation.
- Added explicit command/evidence record and phase-by-phase status rather than treating `.gitkeep` placeholders or fixtures as deliverables.
- Added policy-pack tamper, control-ID, exclusion and coverage unit tests plus API route presence assertions.
- Added the first report-worker library slice: frozen typed report model and deterministic JSON/HTML/CSV rendering with safe output tests. This is not yet wired to database results or downloads; PDF remains pending.
- Added bounded five-field cron parsing and UTC occurrence calculation with explicit spring-forward skip and fall-back earlier-fold semantics; durable schedule persistence and execution are still pending.
- Verified local PostgreSQL migration head and all available Python checks with DB integration enabled; ran frontend typecheck, unit tests, production build and synthetic E2E tests.

## Exact next step

Section 21's dependency order starts with **P0-01**: obtain named owners and authorized representative labs for the frozen platform/build/role rows, then close P0-02 content rights before any CIS-derived pack is distributed. In code, after the blocking G0 evidence is available, proceed to **P0-04** Windows/IOS XE/FortiGate read-only spikes and complete P1's evidence and scan-to-result vertical slice. Do not bypass these gates by claiming fixture output as support.

## Update 2026-10-29 (local completion pass)

Working and locally verified: migrations through 0005 (0004 was repaired), offline evidence import, evaluator pipeline, findings lifecycle, exceptions with independent approval, JSON/HTML/CSV reports, policy catalog, asset register/archive UI, cron schedules with an idempotent tick (live adapters only), two-assessment drift comparison, and a rebuilt web UI. Run `tools/dev.ps1` for the demo.

Still not done, and not claimable: live-device validation of any adapter (needs authorized labs), Windows/firewall/ASA/Check Point/Sophos/PAN-OS adapters, PDF export, SSO/OIDC, remote collectors, manual-review UI, policy editor UI, performance/restore drills, independent security review, and CIS content rights. Deployment is deliberately pending. G0-G5 remain unpassed.

Added later the same day: PDF export (dependency-free text layout), manual-review recording (never resolves a finding), and a policy draft/publish UI. Remaining items are listed above and are blocked on external labs, content rights, or independent reviewers.
