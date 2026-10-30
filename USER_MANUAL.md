# 🛡️ Bastion: Complete User Manual, Developer Guide & Demo Runbook

> **System Overview:** **Bastion — Every Control. Verified.** is a deterministic, CIS-style configuration compliance and hardening auditor (its 103 controls are original, project-authored rules, not licensed CIS Benchmark text). It continuously audits heterogeneous operating systems (Linux, Windows Server/Workstation) and network appliances (Cisco IOS XE, Fortinet FortiOS) with zero AI/ML inference, tamper-evident SHA-256 hash chaining, multi-tenant PostgreSQL Row-Level Security (RLS), and dual-custody risk exception workflows. Features a premium Semgrep-inspired developer landing page and interactive verification sandbox.

> **More documentation:** [docs/README.md](docs/README.md) (index) · [Ubuntu lab onboarding runbook](docs/runbooks/ubuntu-lab-onboarding.md) · [Manual UI test guide](docs/testing/ui-test-guide.md) · [Demo-day runbook](docs/runbooks/demo-day.md)

---

## 📑 Table of Contents
1. [Developer Operations Guide (Running the Stack)](#1-developer-operations-guide)
2. [Web Application User Manual (Step-by-Step UI Guide)](#2-web-application-user-manual)
3. [Live Local Machine Audit (Auditing Your Own PC)](#3-live-local-machine-audit)
4. [Simulated Network Targets (Cisco & Linux Mock Daemons)](#4-simulated-network-targets)
5. [Tomorrow's Demo Presentation Runbook (Step-by-Step Script)](#5-tomorrows-demo-presentation-runbook)
6. [Evaluator & Professor Q&A Defense Cheat-Sheet](#6-evaluator--professor-qa-defense-cheat-sheet)

---

## 1. Developer Operations Guide

### 1.1 Architecture & Ports
* **Database**: PostgreSQL 17 on `127.0.0.1:55432` (Dockerized, tenant RLS enabled)
* **Backend API & Collector Worker**: FastAPI on `http://127.0.0.1:8000`
* **Web Frontend Dashboard**: React 19 + Vite on `http://127.0.0.1:5173`
* **Mock Network Target (SSH)**: Pure-Python Paramiko Daemon on `127.0.0.1:2222`

---

### 1.2 Daily Startup Sequence (3 Commands)

Open PowerShell in the project directory (`D:\mini_proj_hack`):

#### Terminal 1: Database & Background API
```powershell
# 1. Ensure PostgreSQL is running
docker compose -f deploy/compose/compose.yaml up -d

# 2. Start the API with embedded workers enabled
.\.venv\Scripts\python.exe -m baselineguard_api
```
*(Confirms with: `Uvicorn running on http://127.0.0.1:8000` and `embedded collector and evaluator workers started`)*.

#### Terminal 2: Web Frontend
```powershell
corepack pnpm --filter @baselineguard/web dev
```
*(Confirms with: `VITE ready ... Local: http://127.0.0.1:5173/`)*.

#### Terminal 3 (required for live device audits): Mock network devices
```powershell
.\.venv\Scripts\python.exe tools/mock_targets.py
```
*(Confirms with: `listening on 127.0.0.1:2222` and `Simulates: Ubuntu 22.04 LTS, Cisco Catalyst 9300 (IOS XE 17.12), FortiGate 100F (FortiOS 7.4)`)*.

`.env` must contain (already set on this machine; all three are refused when `BG_ENVIRONMENT=production`):
```
BG_DEMO_LOGIN=true      # one-click demo sign-in (skips MFA)
BG_LAB_TARGETS=true     # allow the loopback mock devices on 127.0.0.1:2222
BG_EMBEDDED_WORKERS=true
BG_WORKER_DATABASE_URL=...   # role not limited by RLS (local postgres superuser); see .env.example
```

---

### 1.3 Bringing the demo fleet up to full scope
`tools/sync_demo.py` upgrades the existing organization in place (users and MFA secrets untouched) and is safe to re-run:
```powershell
# With Terminals 1 and 3 running:
.\.venv\Scripts\python.exe tools/sync_demo.py --load
```
It registers the current rule packs (**103 controls**: Windows 32, Cisco IOS-XE 31, FortiGate 20, Ubuntu 20), publishes the
*Enterprise Hardening Baseline (Multi-Platform)* policy, adds Windows Server / Cisco router / FortiGate sample assets, and adds
**live** assets — `core-sw-01` (Cisco switch), `edge-fw-01` (FortiGate), `lab-ubuntu-01` (Ubuntu) on the mock device, plus this
Windows PC — with the mock device's host key pinned. `--load` imports sample evidence and runs a real live scan (≈5 s).

> Note: on this Windows PC, password/lockout and audit-policy controls show **UNKNOWN** unless the API runs from an elevated
> (Administrator) terminal — Windows only reveals them to administrators. This is reported honestly, never as PASS or FAIL.

---

### 1.4 Generating 2FA Authenticator Codes (TOTP)
BaselineGuard enforces enterprise Multi-Factor Authentication. Whenever the UI prompts for a 6-digit code:
```powershell
.\.venv\Scripts\python.exe tools/totp.py
```
Outputs current rolling codes valid for ~30 seconds:
```text
ava      189785   (valid ~28s)
rowan    728156   (valid ~28s)
```

---

## 2. Web Application User Manual

### 2.1 Sign-In & Authentication
1. Navigate to **[http://127.0.0.1:5173](http://127.0.0.1:5173)** (the landing page) and click **Open console** (or **Sign in**), which opens `/login`.
2. Enter the credentials:
   * **Organization**: `northwind`
   * **Username**: `ava` *(Platform Admin & Auditor)* or `rowan` *(Risk Approver)*
   * **Password**: `BaselineGuard-Demo-2026` on this demo machine (pre-filled). A freshly seeded database gets a random password. Use the one stored in `data/demo-credentials.json`.
3. Click **Continue**.
4. When the **Authenticator Code** dialog appears, run `.\.venv\Scripts\python.exe tools/totp.py` and enter the 6-digit number displayed next to your username.

**Quick demo sign-in (skips MFA):** set `BG_DEMO_LOGIN=true` in `.env` and restart the API. The sign-in page then shows **Quick demo access** buttons for `ava` and `rowan` — one click, no authenticator code. To *show* MFA quickly instead, click **Continue** and then **Auto-fill demo code** on the verify step (it types the live code and signs in in ~2 seconds). The password is still checked, every use is written to the audit log as `demo-password-only`, and the API refuses to start if this flag is set with `BG_ENVIRONMENT=production`.

---

### 2.2 Navigation Overview
* **📊 Dashboard (`/`)**: High-level executive posture, fleet compliance percentage, open findings by severity, and drift telemetry.
* **🖥️ Assets (`/assets`)**: Fleet management across Linux, Windows Server, Cisco switches/routers, and Fortinet firewalls. Includes the **Bulk CSV Importer**.
* **📜 Policies (`/policies`)**: The published baseline and its 103 controls. Policy drafts have a **Preview Impact** drawer.
* **🔎 Assessments (`/assessments`)**: Detailed execution logs of audit runs, canonical evidence SHA-256 digests, and pass/fail states.
* **⏱️ Schedules (`/schedules`)**: Cron schedules per site for live assets.
* **⚠️ Findings (`/findings`)**: Granular compliance deviations, expected vs. actual values, and native CLI remediation scripts.
* **🛡️ Exceptions (`/exceptions`)**: Dual-custody risk exemptions workflow. Submit compensatory controls and approve/reject risk waivers.
* **📑 Reports (`/reports`)**: Generate PDF, HTML, CSV and JSON reports. Each is stored encrypted, its SHA-256 is checked on download, and every download is audited.

---

### 2.3 Key Feature Walkthroughs

#### A. Bulk CSV Asset Import (Enterprise Scale)
1. Navigate to **Assets** (`/assets`).
2. Click the **"Import CSV"** button at the top right.
3. Choose a **Default site**, then click **"Insert sample"** to load three valid rows (Linux server, FortiGate, Cisco switch).
4. Click **"Validate rows"**. Each row is checked for category (windows/linux/firewall/router/switch), port within the site's allowed ports, a resolvable site, and duplicates. Invalid rows are listed as "Row N (name): …".
5. Click **"Commit N assets"**. The valid rows are inserted in one transaction under the tenant's row-level security.

#### B. Policy Hardening & Blast Radius Simulation
1. Navigate to **Policies** (`/policies`).
2. Create a policy draft (or pick an existing draft) in the policy editor.
3. Click **"Preview Impact"** on the draft:
   - The drawer evaluates the draft's controls against the latest snapshot of every in-scope asset.
   - Shows total assets affected and how many controls will flip from `PASS` to `FAIL` before you publish.

#### C. Risk Exception & Compensating Control (Dual-Custody)
1. In **Findings** (`/findings`), find a failing control on a critical server (e.g. `ip_forward` or `password_length`).
2. Open the finding and click **"Request exception"**:
   - Enter Business Justification: *"Legacy application dependency requires unencrypted backend port."*
   - Enter Compensating Controls: *"Firewall perimeter ACL restricts access exclusively to administrative jump hosts."*
   - Choose **Expires in** (7/30/60/90 days) and click **Submit for approval**.
3. Log out and sign in as **`rowan`** (*Risk Approver*).
4. Navigate to **Exceptions** (`/exceptions`) and click **"Approve"**.
5. The finding becomes **RISK_ACCEPTED** (see Findings → Accepted). The decision is recorded in the audit log. The requester can never approve their own exception.

---

## 3. Live Local Machine Audit

BaselineGuard includes a read-only local adapter that can audit **the actual Windows machine you are presenting on**.

### Running the Live Audit:
Open PowerShell:
```powershell
.\.venv\Scripts\python.exe tools/audit_local_machine.py
```

### What Happens Behind the Scenes:
1. **Zero-Impact Collection**: Runs 6 non-destructive read-only queries (Registry keys, Windows Defender Firewall profile states, running services, and audit policies).
2. **Cryptographic Hashing**: Hashes raw command outputs with SHA-256 for evidentiary integrity.
3. **Deterministic Evaluation**: Evaluates all facts against the CIS baseline rules.
4. **Live Terminal Report**:
   - Lists compliant controls in green (`[PASS]`).
   - Lists non-compliant controls in red (`[FAIL]`) with exact Observed vs. Expected values and remediation instructions!

---

## 4. Simulated Network Targets

To demonstrate scanning network infrastructure (routers, switches, firewalls) without physical hardware:

### 4.1 The Mock SSH Target
1. Start the daemon in a terminal:
   ```powershell
   .\.venv\Scripts\python.exe tools/mock_targets.py
   ```
2. The daemon runs on `127.0.0.1:2222` with credentials `audituser` / `auditpass`.
3. It answers the exact read-only commands of **Ubuntu 22.04 LTS**, **Cisco IOS XE (Catalyst 9300, 17.12)** and **FortiGate 100F (FortiOS 7.4)**. All three use the same host key.

To audit **real Ubuntu machines** on a lab network, follow [docs/runbooks/ubuntu-lab-onboarding.md](docs/runbooks/ubuntu-lab-onboarding.md). For **another Windows PC**, follow [docs/runbooks/windows-lab-onboarding.md](docs/runbooks/windows-lab-onboarding.md).

### 4.2 Interactive Verification
To show the evaluators that the mock target is a real, responsive SSH service:
```powershell
.\.venv\Scripts\python.exe tools/ssh_client.py
```
Type Cisco commands to see live responses:
* `show version`
* `show interfaces switchport`
* `show spanning-tree summary`
* `exit`

---

## 5. Tomorrow's Demo Presentation Runbook

Use this 6-act narrative script to guide your presentation.

| Duration | Act | Theme & Action | Talking Points |
|:---:|---|---|---|
| **0:00 - 1:00** | **Act 1: The Problem** | Open Dashboard (`http://127.0.0.1:5173`) | *"Most compliance audits are done manually once a year via spreadsheets, screenshots, and guesswork. Configurations drift within days. BaselineGuard automates this with 100% mathematical determinism and forensic audit proof."* |
| **1:00 - 2:30** | **Act 2: Live Local Machine Audit** | Run `tools/audit_local_machine.py` in PowerShell | *"We don't just rely on static mocks. Watch BaselineGuard audit the actual Windows host running this presentation right now in under 4 seconds."* Point out the live PASS/FAIL and SHA-256 proof. |
| **2:30 - 4:00** | **Act 3: Heterogeneous Fleet & Bulk Import** | Navigate to `/assets` and open CSV Import modal | *"Enterprise environments are diverse. Here you see Linux servers, Windows Domain Controllers, Fortinet firewalls, and Cisco switches. With our CSV Bulk Importer, sysadmins can import hundreds of assets with live syntax validation and dry-run previews."* |
| **4:00 - 5:30** | **Act 4: Policy Impact Simulator** | Open `/policies` and click **"Preview Impact"** | *"Before a CISO pushes a stricter security policy, how do they know it won't break 50 servers? Our Policy Impact Engine simulates the blast radius against historical telemetry before publishing."* |
| **5:30 - 7:00** | **Act 5: Dual-Custody Governance** | Log in as `rowan` on `/exceptions` | *"In the real world, you cannot fix 100% of issues immediately. BaselineGuard supports formal Risk Exceptions with compensating controls, expiration dates, and dual-custody approval so audits stay green legally."* |
| **7:00 - 8:30** | **Act 6: Evidence Integrity** | Open a finding in `/findings` and show **Evidence** (`sha256:…`), then a report's digest in `/reports` | *"Every snapshot carries a SHA-256 digest of its normalized evidence, results are written to immutable tables, and every security action is appended to a per-organization SHA-256 audit hash chain that database triggers protect from edits."* |

---

## 6. Evaluator & Professor Q&A Defense Cheat-Sheet

#### Q1: "Why don't you use an AI/LLM to evaluate compliance?"
> **Answer:** *"LLMs are probabilistic and prone to hallucinations. In compliance and regulatory auditing (SOC 2, ISO 27001, PCI-DSS), non-deterministic outputs are disqualifying. An auditor requires mathematical determinism: given the same system configuration, the engine must return the exact same PASS/FAIL verdict 100 times out of 100. We reserve automation for pure-code deterministic evaluation."*

#### Q2: "Can this tool modify or break my servers?"
> **Answer:** *"No. BaselineGuard enforces a strict read-only audit philosophy. The adapters execute non-invasive inspection queries (e.g. `auditpol /get /category:* /r`, `show running-config`, `sysctl -n <specific keys>`, `sshd -T`). We generate native remediation code for sysadmins to review and apply, but we never push unauthorized configuration changes into production."*

#### Q3: "How does it protect against insider database tampering?"
> **Answer:** *"Every snapshot's normalized facts are hashed with SHA-256, each result set records an engine digest that binds the policy, rule packs and snapshot, and those tables are immutable via database triggers. Every security-relevant action is also appended to a per-organization SHA-256 hash chain in the audit log. In addition, PostgreSQL Row-Level Security ensures that tenant data is isolated at the database engine level, preventing cross-organization data leakage even if an API route is compromised."*

#### Q4: "How does this connect to real physical equipment?"
> **Answer:** *"The same adapter classes (`UbuntuSSHReader`, `CiscoIOSXEReader`, `FortiGateReader`) connect to real devices over standard SSH (paramiko). The mock daemon speaks the same SSH protocol on port 2222. To move to real hardware, create a site whose allowed CIDRs and ports cover the device, add the asset, confirm and pin its host-key fingerprint with **Connect**, and scan. Windows is audited locally on the machine running Bastion (`WindowsReader`); remote WinRM collection is not implemented."*

