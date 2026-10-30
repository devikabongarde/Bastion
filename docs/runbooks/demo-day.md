# Runbook: demo day

Use this runbook to bring up the full stack on the demo laptop (Windows, repository at `D:\mini_proj_hack`) and walk through a reliable demo. For a full click-by-click test plan, see [testing/ui-test-guide.md](../testing/ui-test-guide.md).

## Required `.env` flags

Check these before starting. All of them are refused when `BG_ENVIRONMENT=production`.

```
BG_EMBEDDED_WORKERS=true      # collector/evaluator/scheduler run inside the API
BG_WORKER_DATABASE_URL=...    # role not limited by RLS (seed_demo.py writes the dev superuser URL)
BG_DEMO_LOGIN=true            # "Quick demo access" buttons + "Auto-fill demo code"
BG_LAB_TARGETS=true           # allow the mock devices on 127.0.0.1:2222
BG_DOCS_ENABLED=true          # needed only for tools/dev.ps1's health probe
```

## Startup sequence

Use three PowerShell windows in the repository root.

| # | Window | Command | Ready when |
|---|---|---|---|
| 1 | DB | `docker compose -f deploy/compose/compose.yaml up -d` | `docker compose -f deploy/compose/compose.yaml ps` shows `healthy` |
| 2 | API | `.\.venv\Scripts\python.exe -m baselineguard_api` | `Uvicorn running on http://127.0.0.1:8000` and `embedded collector and evaluator workers started` |
| 3 | Mock devices | `.\.venv\Scripts\python.exe tools/mock_targets.py` | `listening on 127.0.0.1:2222` and the "Simulates: Ubuntu 22.04 LTS, Cisco Catalyst 9300 (IOS XE 17.12), FortiGate 100F (FortiOS 7.4)" banner |
| 4 | Web | `corepack pnpm --filter @baselineguard/web dev` | `Local: http://127.0.0.1:5173/` |

Run the API **from an elevated (Administrator) terminal** if you want the Windows password/lockout and audit-policy controls to show PASS/FAIL instead of `UNKNOWN`.

Optionally, bring the demo data fully up to date. This is safe to repeat, and it runs a real live scan against the mock devices and this PC (about 5 s):

```powershell
.\.venv\Scripts\python.exe tools/sync_demo.py --load
```

Expected output: `live scan finished: COMPLETED` (or `PARTIAL` when some Windows controls are UNKNOWN). Each `--load` run signs in as `ava` once.

## Sign-in

- Org `northwind`. Users `ava` (platform admin, scan operator, auditor, author) and `rowan` (risk approver, policy approver).
- The password is stored in `data/demo-credentials.json`. On this machine it is the value given in `USER_MANUAL.md`, and the sign-in form pre-fills it.
- **Quick demo access** buttons sign in without MFA.
- To show MFA, click **Continue**, then **Auto-fill demo code**. Alternatively, read a code from `.\.venv\Scripts\python.exe tools/totp.py`.
- **Rate limit:** 20 attempts per account per 15 minutes (100 per source IP). Demo-login clicks and `sync_demo.py --load` count toward it. Don't use the budget up while rehearsing.

## Pre-demo checklist

- [ ] `http://127.0.0.1:8000/health/ready` returns `{"status":"ready"}`
- [ ] `http://127.0.0.1:5173/` shows the landing page; **Open console** leads to `/login`
- [ ] Quick demo sign-in as `ava` works; Overview shows assets with compliance %
- [ ] Assets: the live assets (`core-sw-01`, `edge-fw-01`, `lab-ubuntu-01`, this PC) show a pinned fingerprint and **Scan**
- [ ] **Scan all live** finishes within seconds (mock devices running)
- [ ] Findings list loads; a finding opens the detail drawer with expected vs. actual values and remediation
- [ ] Exceptions shows at least one approved exception (created by `seed_demo.py --load`)
- [ ] Reports: generating a PDF downloads a file
- [ ] (Optional) A real Ubuntu machine is onboarded per [the Ubuntu runbook](ubuntu-lab-onboarding.md) and its preflight passes on the venue network

## Suggested demo flow

| Step | Screen / command | What it shows |
|---|---|---|
| 1 | Landing page → Open console → Quick demo access (ava) | Product, sign-in, demo mode (audited as `demo-password-only`) |
| 2 | Overview | Compliance next to completeness, open findings by severity, freshness |
| 3 | Terminal: `.\.venv\Scripts\python.exe tools/audit_local_machine.py` | Live, read-only audit of this Windows PC with PASS/FAIL and observed vs. expected values |
| 4 | Assets → **Scan all live** | Real SSH collection from the mock Cisco/FortiGate/Ubuntu devices and a local Windows audit through the job queue |
| 5 | Assets → Connect on a new live asset | Host-key fingerprint shown, compared and pinned before any credential is used |
| 6 | Assessments | Runs, per-target state, result digests (SHA-256) |
| 7 | Findings → detail | Expected vs. actual values, evidence pointer, remediation template, owner/due date |
| 8 | Findings → Request exception; sign out; sign in as `rowan` → Exceptions → Approve | Dual custody. The requester cannot approve their own exception (`SELF_APPROVAL_DENIED`). |
| 9 | Policies → draft → impact preview | Projected status changes before publishing; the author cannot publish their own draft |
| 10 | Reports → PDF / JSON | Hash-checked, audited downloads |
| 11 | `.\.venv\Scripts\python.exe tools/ssh_client.py` (optional) | The mock device is a real SSH server answering `show version`, etc. |

## Recovery

| Symptom | Fix |
|---|---|
| Scans stay `QUEUED` | API started without `BG_EMBEDDED_WORKERS=true`, or `BG_WORKER_DATABASE_URL` points to `bg_api`. Fix `.env`, restart the API. |
| Live scan takes about a minute, then the lab assets show ERROR | The mock device is not reachable. Linux SSH errors are retried twice (20 s, then 40 s) before the scan fails closed. Start `tools/mock_targets.py` and rescan. |
| Mock assets fail with `TARGET_ADDRESS_PROHIBITED` | `BG_LAB_TARGETS` not `true`, or the API was not restarted after changing it |
| Mock assets fail with an SSH error after `data/` was cleaned | The mock host key changed. Restart `mock_targets.py` (it regenerates `data/mock_ssh_host_rsa.key`), then re-run `tools/sync_demo.py`, which rewrites the `[127.0.0.1]:2222` known_hosts entry. The fingerprint shown in the UI comes from the old trust row; use Connect → Re-pin to refresh it. |
| "Too many authentication attempts" | Wait 15 minutes (`Retry-After: 900`) |
| Port 8000/5173 in use | Stop the other process, or use `tools/dev.ps1 -ApiPort / -WebPort` |
