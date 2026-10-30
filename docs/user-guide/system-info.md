


### High-Level Architecture Overview

```
                   ┌──────────────────────────────────────────────┐
                   │           Frontend (React 19 / Vite)         │
                   │  Semgrep design system · TanStack · Tailwind │
                   └──────────────────────┬───────────────────────┘
                                          │ REST / OpenAPI
                   ┌──────────────────────▼───────────────────────┐
                   │           FastAPI Backend (Port 8000)         │
                   │  Argon2id · TOTP MFA · Fernet Envelope Crypto│
                   └──────┬──────────────────┬─────────────────┬──┘
                          │                  │                 │
         ┌────────────────▼──┐    ┌──────────▼────────┐   ┌────▼─────────────┐
         │ PostgreSQL 17 DB  │    │ Deterministic     │   │ Target Adapters  │
         │ (SQLAlchemy ORM)  │    │ Rule Engine (AST) │   │ (SSH / Paramiko) │
         └───────────────────┘    └───────────────────┘   └──────┬───────────┘
                                                                 │
                                    ┌────────────────────────────┼──────────────────────────┐
                                    ▼                            ▼                          ▼
                             [Linux Targets]             [Windows Targets]          [Cisco / FortiGate]
                             Paramiko SSH (port 22)      OpenSSH + PowerShell       VT100 interactive SSH
```

---

### 1. Collector & Target Adapters (`packages/adapters`)
*All connections are strictly agentless, read-only, and non-destructive.*

* **Linux Adapter (`linux/ssh.py`, `linux/reader.py`)**:
  * Uses **Paramiko SSH** with host-key verification and strict timeouts.
  * Runs a fixed catalog of 14 read-only commands: `sysctl -a`, reading `/etc/login.defs`, `/etc/pam.d/common-password`, `/etc/ssh/sshd_config`, checking file permissions on `/etc/shadow` and `/etc/passwd`.
  * Protects targets with strict size ceilings (`MAX_READER_BYTES = 1MB`) to prevent memory exhaustion attacks.
* **Windows Adapter (`windows/reader.py`)**:
  * Connects over **Windows native OpenSSH** on TCP 22.
  * Executes 6 atomic PowerShell commands:
    * `Get-CimInstance Win32_OperatingSystem` (Identity)
    * Registry inspections via `Get-ItemProperty` (UAC, SMBv1, RDP, screensaver timeout)
    * `secedit /export` (Password length, account lockout)
    * `auditpol.exe /get /category:* /r` (Logon & privilege auditing)
    * `Get-NetFirewallProfile` (Domain, Private, Public firewall rules)
    * `Get-Service` (Flags insecure services: Telnet, RemoteRegistry, SSDPSRV).
* **Cisco IOS XE Adapter (`cisco/`)**:
  * Launches an interactive VT100 pseudo-terminal shell.
  * Disables paging with `terminal length 0`.
  * Runs `show running-config`, `show version`, `show access-lists`, `show interfaces switchport`.
  * Parses raw CLI blocks into typed JSON dictionary structures.
* **FortiGate Adapter (`fortigate/`)**:
  * Ingests and tokenizes FortiOS hierarchical block configurations (`config system global`, `config firewall policy`).

---

### 2. Deterministic Rule & Assessment Engine (`packages/engine`)
*This is the core differentiator: zero AI/LLM hallucinations, 100% reproducible math.*

* **Abstract Syntax Tree (AST) Evaluator**:
  * Parses policy rules written in declarative YAML/JSON format.
  * Supports deterministic operators: `equals`, `not_equals`, `greater_than_or_equal`, `regex_match`, `cidr_contains`, `in_set`, `file_mode_le`.
* **Honest 6-State Result Classifier**:
  * **`PASS`**: Condition strictly satisfied by verified evidence.
  * **`FAIL`**: Condition explicitly violated (e.g. idle timeout is 0 instead of ≤ 300).
  * **`UNKNOWN`**: Target returned unexpected syntax; engine refuses to guess.
  * **`ERROR`**: Command failed, connection timed out, or permission was denied.
  * **`MANUAL_REQUIRED`**: Rule mandates a physical or human check.
  * **`NOT_APPLICABLE`**: Control is tailored out or platform does not apply.
* **Dual Integrity Metrics**:
  * **Evaluated Compliance %**: `PASS / (PASS + FAIL)`
  * **Assessment Completeness %**: `Evaluated Controls / Total Controls In Policy`
  * *Prevents fake 100% compliance scores where failed checks are hidden.*
* **Cryptographic Evidence Replay**:
  * Every raw string output from target commands is hashed via **SHA-256**.
  * Outputs are assembled into an immutable assessment manifest that auditors can verify offline anytime.

---

### 3. Backend & Security Architecture (`apps/api`)
*Built on **FastAPI**, **Pydantic v2**, and **SQLAlchemy 2.0 async**.*

* **Authentication & Identity**:
  * **Argon2id** password hashing (`m=65536, t=3, p=4`).
  * **TOTP MFA** (RFC 6238 compliant) enforced at login with a dedicated step-up token.
  * **Session Tokens**: Cryptographically signed Bearer tokens stored in HTTP-only cookies or authorization headers.
* **Role-Based Access Control (RBAC)**:
  * Strict privilege separation:
    * `platform_admin`: User & target management.
    * `auditor`: Trigger scans, view findings, export evidence.
    * `risk_approver`: Grant and review risk exceptions.
    * `policy_author`: Tailor and publish versioned baseline policies.
* **Credential Vault & Cryptography**:
  * Stored SSH passwords and private keys are encrypted using **Fernet symmetric envelope encryption**.
  * Ciphertext is cryptographically bound to the organization ID to prevent cross-tenant decryption.
* **Policy Draft & Approval Workflow**:
  * Policies are immutable once published.
  * Any edit creates a draft with an **Impact Preview**: computes how many assets will flip from PASS to FAIL *before* the policy is published.

---

### 4. Frontend Web Console & Landing Page (`apps/web`)
*Built on **React 19**, **Vite**, **TypeScript**, **Tailwind CSS**, and **TanStack Query/Table**.*

* **Design System (Inspired by Semgrep)**:
  * Minimalist, calm, evidence-first aesthetic.
  * Color tokens: `--forest: #2F3E39`, `--accent: #1FCB9B`, `--mint-tint: #DCEEE5`, `--bg: #F7F7F5`.
  * Typography: Inter for UI text, **Geist Mono** for hashes, CLI commands, and rules.
* **WCAG 2.2 AA Compliance**:
  * Status badges **never rely on color alone**; each badge pairs an icon with explicit text (`PASS [✓]`, `FAIL [✕]`, `ERROR [⚠]`).
* **Interactive UI Pages**:
  * **`/landing`**: Edge-to-edge product landing page with interactive interactive code previews, platform marquee, and feature spotlight cards.
  * **`Overview`**: Compliance dials, completeness gauges, and recent assessment activity.
  * **`Assessments`**: One-click target auditing with real-time state transitions (`PENDING -> COLLECTING -> EVALUATING -> COMPLETED`).
  * **`Findings`**: Filterable finding grid with drawer displaying raw evidence, SHA-256 checksums, and reviewed copy-paste remediation CLI fixes.
  * **`Assets`**: Target inventory with CSV import/export, health preflight checks, and connectivity testing.
  * **`Policies & Policy Editor`**: Visual policy builder with exclusion toggles and pre-publication impact simulation.
  * **`Exceptions`**: Time-bounded risk waiver workflow with review dates and audit logging.

---

### 5. Mock Simulation & Test Harness (`tools/`)
* **`tools/mock_targets.py`**:
  * Embedded Paramiko SSH server running on `127.0.0.1:2222`.
  * Simulates both an **Ubuntu 22.04 LTS server** and a **Cisco IOS XE switch** directly in memory.
  * Allows end-to-end demonstrations without needing physical routers or external virtual machines.
* **`tools/totp.py`**:
  * Real-time command-line RFC 6238 TOTP code generator for test accounts.
* **Test Coverage**:
  * **107 Python unit & integration tests** (`pytest`).
  * **8 Web unit tests** (`vitest`).
  * **3 Playwright end-to-end browser tests** verifying zero regressions on navigation, responsiveness, and access controls.

When a scan completes in Bastion, the data is stored using a **two-tier architecture**: **structured metadata** goes into PostgreSQL, while the **raw evidence** goes into an encrypted, tamper-evident artifact volume.

Here is the exact breakdown:

---

### 1. The Two-Tier Storage Architecture

| Layer | What Is Stored | Storage Technology & Format |
| :--- | :--- | :--- |
| **Tier 1: Structured Scan Database** | Findings, pass/fail status, expected vs. actual values, scores, timestamps, and audit events | **PostgreSQL 17** via **JSONB** and relational tables |
| **Tier 2: Tamper-Evident Evidence Vault** | Raw target command outputs (sysctl, secedit, show running-config, etc.) | **Content-addressed encrypted files** (`AES-256-GCM` + `SHA-256`) & **Ed25519-signed JSON manifests** |

---

### 2. Tier 1: The Database Format (`PostgreSQL 17`)

Stored across relational models in [`packages/persistence/src/baselineguard_persistence/models.py`](file:///d:/mini_proj_hack/packages/persistence/src/baselineguard_persistence/models.py):

* **`result_sets` table**:
  * Captures the overall scan session for an asset.
  * Contains cryptographic hashes of the evaluation engine (`engine_digest`) and policy (`semantic_digest`) to guarantee reproducibility.
  * `summary` (`JSONB`): Stores aggregated counts: `{ "total": 45, "pass": 34, "fail": 8, "error": 1, "compliance_pct": 80.95 }`.
* **`control_results` table**:
  * One row per evaluated CIS control.
  * `status`: Strict enum (`PASS`, `FAIL`, `UNKNOWN`, `ERROR`, `MANUAL_REQUIRED`, `NOT_APPLICABLE`).
  * `expected` (`JSONB`): The expected policy baseline (e.g., `{"exec_timeout_seconds": "<= 300"}`).
  * `actual` (`JSONB`): What was actually extracted from the target (e.g., `{"exec_timeout_seconds": 0}`).
  * `trace` (`JSONB`): Evaluation execution trace detailing exact line numbers and match expressions.
* **`findings` table**:
  * Active persistent vulnerabilities that require remediation, tracking first seen, last observed, and exception status.

---

### 3. Tier 2: The Raw Evidence Vault Format (`AES-256-GCM` & Signed Manifest)

Raw machine configurations (passwords, shadow files, firewall configs) **never touch plain SQL columns**. Instead, they are handled by the evidence subsystem ([`packages/evidence/src/baselineguard_evidence/bundle.py`](file:///d:/mini_proj_hack/packages/evidence/src/baselineguard_evidence/bundle.py)):

1. **Content-Addressed Encryption (`AES-256-GCM`)**:
   * Each raw command output is encrypted with **AES-256-GCM** with authenticated data binding (`org:<id>:artifact:<id>`).
   * The file name on disk is the **SHA-256 hexadecimal hash** of the unencrypted plaintext content.
2. **Signed Manifest (`manifest.json`)**:
   * A signed cryptographic JSON document with schema version `1.0`:
     ```json
     {
       "schema_version": "1.0",
       "org_id": "9b1deb4d-...",
       "scan_run_id": "c1f7a83d-...",
       "created_at": "2026-10-30T10:45:00Z",
       "artifacts": [
         {
           "artifact_id": "a4d3...",
           "reader_id": "cisco.cli.running_config",
           "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
           "bytes": 14208
         }
       ],
       "signature": {
         "alg": "Ed25519",
         "public_key": "MCowBQYDK2VwAyEA...",
         "value": "base64_signature..."
       }
     }
     ```
3. **Auditor Offline Export Bundle (`.tar.gz` / `.zip`)**:
   * Auditors can export the complete scan as a single compressed archive containing the `manifest.json`, the redacted artifacts, and a verification script so third-party compliance regulators can cryptographically verify that the evidence was not altered after collection.

---

### Key Takeaway for Presentation
> *"We store high-speed query data like pass/fail status, expected vs actual values, and remediation plans in **PostgreSQL JSONB** tables. But for the raw machine output, we store it in a **content-addressed, AES-256 encrypted evidence vault** signed with **Ed25519** keys. This gives us both sub-second UI dashboard queries and legally defensible cryptographic proof for auditors."*