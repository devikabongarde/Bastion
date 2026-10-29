# 🛡️ BaselineGuard: Complete User Manual, Developer Guide & Demo Runbook

> **System Overview:** BaselineGuard is an enterprise-grade, deterministic CIS Benchmark Compliance & Configuration Hardening platform. It continuously audits heterogeneous operating systems (Linux, Windows Server/Workstation) and network appliances (Cisco IOS XE, Fortinet FortiOS) with zero AI/ML inference, tamper-evident SHA-256 hash chaining, multi-tenant PostgreSQL Row-Level Security (RLS), and dual-custody risk exception workflows.

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

#### Terminal 3 (Optional for Network Simulation): Mock SSH Daemon
```powershell
.\.venv\Scripts\python.exe tools/mock_targets.py
```
*(Confirms with: `Mock Target SSH Server listening on 127.0.0.1:2222`)*.

---

### 1.3 Seeding Demo Enterprise Fleet
If you ever want to re-seed or refresh the database with 7 heterogeneous enterprise assets, all 120 CIS rule controls, historical compliance assessments, and sample exceptions:
```powershell
# Run with API running in Terminal 1:
.\.venv\Scripts\python.exe tools/seed_demo.py --load
```

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
1. Navigate to: **[http://127.0.0.1:5173](http://127.0.0.1:5173)**
2. Enter the credentials:
   * **Organization**: `northwind`
   * **Username**: `ava` *(Platform Admin & Auditor)* or `rowan` *(Risk Approver)*
   * **Password**: `BaselineGuard-Demo-2026`
3. Click **Sign In**.
4. When the **Authenticator Code** dialog appears, run `.\.venv\Scripts\python.exe tools/totp.py` and enter the 6-digit number displayed next to your username.

---

### 2.2 Navigation Overview
* **📊 Dashboard (`/`)**: High-level executive posture, fleet compliance percentage, open findings by severity, and drift telemetry.
* **🖥️ Assets (`/assets`)**: Fleet management across Linux, Windows Server, Cisco switches/routers, and Fortinet firewalls. Includes the **Bulk CSV Importer**.
* **📜 Policies (`/policies`)**: Active hardening baselines across 120 controls. Includes the **Preview Impact Drawer**.
* **🔎 Assessments (`/assessments`)**: Detailed execution logs of audit runs, canonical evidence SHA-256 digests, and pass/fail states.
* **⚠️ Findings (`/findings`)**: Granular compliance deviations, expected vs. actual values, and native CLI remediation scripts.
* **🛡️ Exceptions (`/exceptions`)**: Dual-custody risk exemptions workflow. Submit compensatory controls and approve/reject risk waivers.
* **📑 Reports (`/reports`)**: Generate signed, audit-proof PDF and JSON compliance exports.

---

### 2.3 Key Feature Walkthroughs

#### A. Bulk CSV Asset Import (Enterprise Scale)
1. Navigate to **Assets** (`/assets`).
2. Click the **"Import CSV"** button at the top right.
3. Click **"Insert Sample Template"** to load a valid multi-platform batch.
4. Click **"Validate CSV"**: Observe row-by-row syntax validation and dry-run preview (checks platform family, valid ports, and addresses).
5. Click **"Commit Import"**: Records are committed atomically into PostgreSQL under the tenant's Row-Level Security envelope.

#### B. Policy Hardening & Blast Radius Simulation
1. Navigate to **Policies** (`/policies`).
2. Select an active baseline (e.g. *Enterprise Hardening Baseline v1*).
3. Click **"Preview Impact"**:
   - The drawer analyzes the proposed control changes against the latest snapshot of every active asset in your fleet.
   - Shows total assets affected and how many controls will flip from `PASS` to `FAIL` before you publish.

#### C. Risk Exception & Compensating Control (Dual-Custody)
1. In **Findings** (`/findings`), find a failing control on a critical server (e.g. `ip_forward` or `password_length`).
2. Click **"Request Exception"**:
   - Enter Business Justification: *"Legacy application dependency requires unencrypted backend port."*
   - Enter Compensating Controls: *"Firewall perimeter ACL restricts access exclusively to administrative jump hosts."*
   - Set Expiration Date: (e.g. 60 days).
3. Log out and sign in as **`rowan`** (*Risk Approver*).
4. Navigate to **Exceptions** (`/exceptions`) and click **"Approve"**.
5. The finding is now formally exempt from the compliance denominator, signed with an audit trail.

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
3. It emulates both **Ubuntu 22.04 LTS** and **Cisco IOS XE Catalyst 9300** network devices.

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
| **7:00 - 8:30** | **Act 6: Cryptographic Hash Chains** | Open `/assessments` and show evidence hashes | *"Every finding is sealed into a tamper-evident SHA-256 hash chain stored in PostgreSQL with Row-Level Security. If an attacker modifies the database, the chain breaks instantly."* |

---

## 6. Evaluator & Professor Q&A Defense Cheat-Sheet

#### Q1: "Why don't you use an AI/LLM to evaluate compliance?"
> **Answer:** *"LLMs are probabilistic and prone to hallucinations. In compliance and regulatory auditing (SOC 2, ISO 27001, PCI-DSS), non-deterministic outputs are disqualifying. An auditor requires mathematical determinism: given the same system configuration, the engine must return the exact same PASS/FAIL verdict 100 times out of 100. We reserve automation for pure-code deterministic evaluation."*

#### Q2: "Can this tool modify or break my servers?"
> **Answer:** *"No. BaselineGuard enforces a strict read-only audit philosophy. The adapters execute non-invasive inspection queries (e.g. `auditpol /get`, `show running-config`, `sysctl -a`). We generate native remediation code for sysadmins to review and apply, but we never push unauthorized configuration changes into production."*

#### Q3: "How does it protect against insider database tampering?"
> **Answer:** *"Every assessment snapshot generates a canonical JSON representation that is hashed with SHA-256 and linked to the previous scan's digest in a cryptographic hash chain. In addition, PostgreSQL Row-Level Security ensures that tenant data is isolated at the database engine level, preventing cross-organization data leakage even if an API route is compromised."*

#### Q4: "How does this connect to real physical equipment?"
> **Answer:** *"The exact same adapter classes (`WindowsReader`, `LinuxSSHReader`, `CiscoIOSXEReader`, `FortiGateReader`) connect to live physical devices over standard SSH (paramiko/netmiko) or WinRM HTTPS. Our mock daemon uses the exact same SSH protocol on port 2222, so transitioning from testing to a live data center rack requires only updating the IP address and credential in the Asset inventory."*

