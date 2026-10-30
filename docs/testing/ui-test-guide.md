# Bastion: manual UI test guide

A click-through checklist for the running console. I wrote it from the current UI code (`apps/web/src`) and the API role checks (`apps/api/src/baselineguard_api/routes/v1`). Where `USER_MANUAL.md` disagrees with the code, this guide follows the code. For example, the sign-in button says **Continue**, not "Sign In", and the CSV buttons are **Insert sample**, **Validate rows** and **Commit N assets**.

- Web: http://127.0.0.1:5173
- API: http://127.0.0.1:8000 (health: http://127.0.0.1:8000/health/live)
- Org `northwind`, password `BaselineGuard-Demo-2026` (check `data/demo-credentials.json` if it was re-seeded)
- `ava`: platform_admin, analyst, scan_operator, auditor, policy_author, inventory_editor, viewer, manual_assessor
- `rowan`: risk_approver, policy_approver, analyst, viewer

> The top bar shows **role names, not the username**. You are ava when the chip reads `platform_admin, analyst +6` and rowan when it reads `risk_approver, policy_approver +2`. The Overview greeting also says `· Platform admin` or `· Risk approver`.

> **Sign-in budget:** the API allows 20 sign-in attempts per account per 15 minutes. Demo-login clicks and `tools/sync_demo.py --load`, which signs in as ava, count toward that limit. Going over it returns "Too many authentication attempts. Try again in 15 minutes." Don't use up the limit on demo morning.

---

## 0. Smoke test in 5 minutes (demo morning)

Do these in order. If any step fails, stop and fix it before the demo.

| # | Check | Expected | ☐ |
|---|---|---|---|
| S1 | Open http://127.0.0.1:8000/health/live | `{"status":"live"}` | ☐ |
| S2 | Open http://127.0.0.1:5173 in a private window | The marketing landing page loads with the "Every … Verified." hero | ☐ |
| S3 | Click **Sign in**, then click the **Ava** card under "Quick demo access" | You land on **Fleet posture**. The sidebar footer shows a green dot and "API connected" | ☐ |
| S4 | Look at the Overview KPIs | Compliance %, Completeness %, Open findings and Assets are all numbers, not "—". "last assessment" is recent | ☐ |
| S5 | Go to **Assets** | The table lists the fleet. `core-sw-01`, `edge-fw-01` and `lab-ubuntu-01` show **Live · SSH** with a **Pinned** host key. Your PC shows **Live · this machine** with **Not applicable** | ☐ |
| S6 | Start the mock targets (see 1.3), then click **Scan all live (N)** on Assets | The button reads **Scanning…**. Within about 5–15 s a toast appears: "Live scan completed — open Assessments to see every check" (or "partial") | ☐ |
| S6b | Go to **Assessments** and click the newest run at the top of **Recent assessments** | A panel lists each scanned asset with pass/fail counts, the evidence digest, and every control with its expected and observed value. **This is where scan output lives** | ☐ |
| S7 | Go to **Findings** and click any row | A drawer opens with "Expected vs. actual configuration", **Evidence** (sha256), **Remediation** and **Copy commands** | ☐ |
| S8 | **Reports**: set Format to **PDF (text layout)**, click **Generate report**, then **Download** | Toast "Report generated from the latest results". A PDF downloads and opens | ☐ |
| S9 | Press **Ctrl+K** | The command palette opens. Type "find", press Enter, and you land on Findings | ☐ |
| S10 | Click **Sign out**, then sign in as **Rowan** and go to **Exceptions** | The register loads. If any exception is REQUESTED by ava, rowan sees **Approve** and **Reject** | ☐ |

---

## 1. Prerequisites and startup

### 1.1 One-time requirements
- Docker Desktop is running. `.env` exists in the repo root and contains `POSTGRES_SUPERUSER_PASSWORD`, `BG_MIGRATION_PASSWORD`, `BG_APP_PASSWORD`, `BG_DEMO_LOGIN=true`, `BG_LAB_TARGETS=true`, `BG_EMBEDDED_WORKERS=true` and `BG_WORKER_DATABASE_URL` (a role not limited by RLS; `.env.example` ships the local `postgres` superuser URL).
- `.venv` exists, and `corepack pnpm install` has been run.
- To set up from scratch, see `docs/development/local-setup.md`.

### 1.2 Start the stack (PowerShell, repo root `D:\mini_proj_hack`)

Terminal 1, the database and API:
```powershell
docker compose -f deploy/compose/compose.yaml up -d
.\.venv\Scripts\python.exe -m baselineguard_api
```
Expected log lines: `Uvicorn running on http://127.0.0.1:8000` and `embedded collector and evaluator workers started`.

Terminal 2, the web app:
```powershell
corepack pnpm --filter @baselineguard/web dev
```
Expected: `VITE ready … Local: http://127.0.0.1:5173/`. Vite proxies `/api` and `/health` to the API.

Terminal 3, the mock SSH devices. You need these for every live SSH scan:
```powershell
.\.venv\Scripts\python.exe tools/mock_targets.py
```
Expected: `listening on 127.0.0.1:2222`. It simulates Ubuntu 22.04, Cisco Catalyst 9300 (IOS XE 17.12) and FortiGate 100F. Mock credentials are `audituser` / `auditpass`.

MFA codes, when you use the real MFA path:
```powershell
.\.venv\Scripts\python.exe tools/totp.py
```
This prints `ava 123456 (valid ~NNs)` and `rowan …`. Codes are single-use per 30 s window.

> Run the API from an **elevated** terminal if you want Windows password, lockout and audit-policy controls to show PASS or FAIL. Without elevation those controls are reported as **UNKNOWN**. That is expected, not a bug.

### 1.3 Reset / seed data
```powershell
# Terminals 1 and 3 running:
.\.venv\Scripts\python.exe tools/sync_demo.py --load
```
- This script is **idempotent and additive**. It re-registers rule packs, makes sure the *Enterprise Hardening Baseline (Multi-Platform)* policy is published, re-adds missing demo assets (Windows fixtures, `branch-rtr-01`, `dmz-fw-02`, live `core-sw-01`, `edge-fw-01`, `lab-ubuntu-01` and this PC), re-pins the mock host key, binds `audituser` credentials, imports sample evidence for assets that have never been assessed, and runs one live scan.
- It does **not** delete anything you created while testing, such as extra assets, exceptions, drafts, schedules or reports. Archive test assets from the asset drawer.
- If you need a true wipe, you would have to delete the Docker volume and run `tools/seed_demo.py`. **Don't do this before the demo.** `seed_demo.py` generates a **random password** and new TOTP secrets, and writes them to `data/demo-credentials.json`. The sign-in form would then be pre-filled with the wrong password.

---

## 2. Test cases

Mark each row ✅ or ❌. "Signed in as X" means use **Quick demo access** unless the step says otherwise.

### 2.1 Landing and docs (signed out)

| ID | Steps | Expected result | Pass/Fail |
|---|---|---|---|
| L-01 | Signed out, open `/` | The landing page renders. Nav: Features, How it works, Security, Docs, **Sign in**, **Open console** | ☐ |
| L-02 | Click **Features**, **How it works** and **Security** in the nav | Each one smooth-scrolls to its section. The URL does not change | ☐ |
| L-03 | In "How it works", click each numbered step tab | The active tab changes and the progress bar animates. Hovering pauses it | ☐ |
| L-04 | Click **Open the console** (hero) | You go to `/login` and the sign-in page appears | ☐ |
| L-05 | Go back, then click **Read the docs** (hero or bottom CTA) | `/docs` opens at the top with the "Bastion documentation" heading | ☐ |
| L-06 | Footer links **Documentation** and **Sign in** | They go to `/docs` and `/login` respectively | ☐ |
| D-01 | On `/docs`, type `exc` in **Search docs…** | The sidebar filters to "Risk exceptions". Typing `zzz` shows "No sections match “zzz”." | ☐ |
| D-02 | Scroll the docs | The sidebar highlights the section in view. The Previous/Next links at the bottom update | ☐ |
| D-03 | Open `/docs#verdicts` directly | The page scrolls to "Verdicts" | ☐ |
| D-04 | Click **Home**, then come back and click **Sign in →** in the docs header | Home goes to `/`: the landing page when signed out, Overview when signed in. **Sign in** goes to `/login` | ☐ |
| D-05 | Visit `/landing` while signed in | The full landing page shows without the sidebar. **Open console** goes to Overview | ☐ |

### 2.2 Sign-in, MFA, session

| ID | Steps | Expected result | Pass/Fail |
|---|---|---|---|
| A-01 | Open `/login` | "Welcome back". Organization, Username and Password are pre-filled with `northwind` / `ava` / ••••. The steps bar shows **1 Credentials** → **2 Verify** | ☐ |
| A-02 | Click the eye icon in the password field | The password is revealed. The label toggles between "Show password" and "Hide password" | ☐ |
| A-03 | Change the password to `wrong-password` and click **Continue** | The button shows "Checking…", then the red alert "The sign-in details are invalid or the account is unavailable." You stay on step 1 | ☐ |
| A-04 | Set the organization to `Northwind!` (uppercase or symbol) and submit | The browser blocks the submit (pattern `[a-z0-9-]+`) | ☐ |
| A-05 | Restore the correct password and click **Continue** | Step 2: "Verify it’s you", "Enter the 6-digit code … for **ava**", and six digit boxes with the first one focused | ☐ |
| A-06 | Run `tools/totp.py` and type ava's code | Focus moves box to box. When the sixth digit is entered it submits automatically, shows "Verifying code…", and you land on Overview | ☐ |
| A-07 | Sign out, reach step 2 again, and **paste** a 6-digit code into the first box | All six boxes fill and it submits | ☐ |
| A-08 | At step 2, enter `000000` | "The challenge or verification code is invalid." The boxes clear for a new attempt. After 5 wrong codes the challenge is dead, so click **Start again** | ☐ |
| A-09 | At step 2, click **Auto-fill demo code** | Digits type in one by one (about 0.7 s) and it signs in. The button is disabled while filling | ☐ |
| A-10 | At step 2, click **Use a recovery code** | The heading changes to "Use a recovery code" with a 20-hex input and a **Verify and sign in** button. Entering `abc` is blocked by the browser. Entering `0123456789abcdef0123` gives "The challenge or verification code is invalid." Click **Use authenticator app** to switch back. (No real recovery codes are stored in the demo data, so you can only test the failure case.) | ☐ |
| A-11 | At step 2, click **Start again** | You return to step 1 and the fields are kept | ☐ |
| A-12 | On step 1, click the **Ava** card under "Quick demo access" | A spinner shows on the card, then Overview opens with no MFA. The note "Demo mode skips MFA. Every demo sign-in is recorded in the audit log." is visible under the cards | ☐ |
| A-13 | Sign out, then click the **Rowan** card | Overview greeting "· Risk approver". The chip reads `risk_approver, policy_approver +2` | ☐ |
| A-14 | Click **Sign out** in the top bar | The button shows "Signing out…", then the landing page appears at the same URL. Pressing Back or reloading still shows the landing page, not data | ☐ |
| A-15 | Sign in, then press **F5** on `/assets` | You stay signed in on Assets. Then perform any write, such as toggling a schedule or generating a report, and it succeeds. This shows the CSRF token is re-read from `/api/v1/me` after a reload | ☐ |
| A-16 | Open the app in two tabs. Sign out in tab 1, then switch to tab 2 and click any action | Tab 2 switches to the landing page on focus or refetch, or the action fails with an error. No data changes are made | ☐ |
| A-17 | While signed in, open `/login` | It redirects to `/` (Overview) | ☐ |
| A-18 | **Back to home** on the sign-in page | Goes to `/`, the landing page | ☐ |
| A-19 | Footer text on the sign-in page | "Protected by MFA · Sessions expire after 12 hours" | ☐ |

### 2.3 Navigation, theme, command palette

| ID | Steps | Expected result | Pass/Fail |
|---|---|---|---|
| N-01 | Click each sidebar item: Overview, Assets, Assessments, Findings, Exceptions, Schedules, Reports, Policies | Each page loads. The active item is highlighted. The breadcrumb reads `Bastion / <Page>` | ☐ |
| N-02 | Look at the **Findings** nav item | It shows a badge with the OPEN finding count, matching Overview "Open findings" | ☐ |
| N-03 | Open `/nonsense` | "Page not found – Choose a view from the primary navigation." | ☐ |
| N-04 | Open `/scans` | It shows the Assessments page (alias route) | ☐ |
| N-05 | Click the moon/sun icon | The theme toggles between dark and light and persists across reloads (`localStorage bg-theme`). The landing, docs and sign-in pages always stay light | ☐ |
| N-06 | Click **Product Landing** in the top bar, or the logo in the sidebar | Goes to `/landing` | ☐ |
| N-07 | Press **Ctrl+K**, or click "Search views & actions… ⌘K" | The palette opens with the placeholder "Type a command or jump to screen…" and two groups, **Navigation** and **Actions** | ☐ |
| N-08 | Choose each item: Overview Dashboard, Target Assets Inventory, Verified Findings & Evidence, Assessment Runs, Policies & CIS Benchmarks, Compliance Reports (PDF/CSV), Bastion Marketing Landing Page | Each one navigates and the palette closes | ☐ |
| N-09 | Actions: **Launch New Fleet Assessment**, **Filter Critical Deviations**, **Toggle Theme (…)** | They go to Assessments, go to Findings with **Critical** pre-selected, and flip the theme | ☐ |
| N-10 | Press Ctrl+K twice, and Esc | Ctrl+K toggles the palette open and closed. Esc closes it | ☐ |
| N-11 | (Known gap) Type "G" then "O" outside the palette | Nothing happens. The "G O / G A …" hints in the palette are labels only (see Known issues) | ☐ |
| N-12 | Press Tab on a fresh page load | "Skip to main content" link appears | ☐ |

### 2.4 Overview

| ID | Steps | Expected result | Pass/Fail |
|---|---|---|---|
| O-01 | Open Overview as ava | "Fleet posture". The subline reads `N assets monitored · last assessment <x ago>` with a pulsing **Live** label | ☐ |
| O-02 | KPI cards | **Compliance** (with ↑/↓ pts and a sparkline when there are 2 or more runs, plus "X of Y evaluated passed"), **Completeness** with a meter, **Open findings** ("N critical/high" or "No critical or high", plus "N resolved") and **Assets** ("x/y fresh evidence") | ☐ |
| O-03 | Click the **Open findings** card, then the **Assets** card | They go to Findings and Assets | ☐ |
| O-04 | Platform cards (Windows / Linux / Firewalls / Routers & switches) | Each shows a compliance figure. Clicking one goes to Assets | ☐ |
| O-05 | "Compliance trend", "Verdict distribution" (Pass/Fail/Unknown/Error/Manual/N/A) | The chart and legend render, and the numbers add up | ☐ |
| O-06 | "Asset posture" (lowest compliance first). Click a row | Goes to `/findings?asset=<id>`. Findings shows a chip `<asset name> ×` | ☐ |
| O-07 | "Open by severity". Click **High** | Goes to Findings filtered to High | ☐ |
| O-08 | "Recent activity" | Events such as "New finding", "Fixed & verified" or "Reopened", with the asset and time | ☐ |
| O-09 | **Export report** / **Run assessment** buttons | They go to Reports / Assessments | ☐ |
| O-10 | Leave Overview open for 15 s after a scan finishes elsewhere | The numbers refresh on their own (15 s polling) | ☐ |

### 2.5 Assets

| ID | Steps | Expected result | Pass/Fail |
|---|---|---|---|
| AS-01 | Open Assets as ava | Header buttons: **Scan all live (N)**, **Import CSV**, **Add asset**. Table columns: Asset, Platform, Collection, Host key, Compliance, Last assessed, Action | ☐ |
| AS-02 | Type `fw` in "Search by name, address or platform…" | Only firewalls remain. Typing `127.0.0.1` filters by address and `windows` filters by platform. Typing `zzz` shows "No assets match." | ☐ |
| AS-03 | Collection chips | Fixtures show **Fixture**, mock devices show **Live · SSH** and your PC shows **Live · this machine**. Host key reads **Pinned** (hover to see the SHA256 fingerprint), **Not pinned**, or **Not applicable** | ☐ |
| AS-04 | Click a fixture row, e.g. `win-dc-01` | The right drawer shows the chip, address:port, name, "platform · role · criticality", Adapter (`windows-fixture`), Host key "Not applicable for this collection mode", Credential "Not required" and Compliance %. Buttons: **View findings** and **Archive asset**. **Close** works | ☐ |
| AS-05 | Click `lab-ubuntu-01` | Host key shows the `SHA256:…` value and "Pinned <date> — any other key is refused." Credential: "Read-only audit credential bound (encrypted at rest)". Buttons: **View findings**, **Scan now**, **Re-pin host key & credential** | ☐ |
| AS-06 | Action column | Ready live assets show **Scan**. Unpinned live SSH assets show **Connect**. Everything else shows **Findings →** | ☐ |
| AS-07 | **Add asset**: Site = Headquarters, Name `ui-test-01`, Address `10.20.5.20`, Port `22`, Category Linux server, Collection **Linux · live SSH**, Role `server`, Criticality high. Click **Add asset** | The drawer closes and `ui-test-01` appears with **Live · SSH**, **Not pinned** and a **Connect** action. (Note: the Headquarters site only allows port 22.) | ☐ |
| AS-08 | **Add asset** with address `8.8.8.8` (or port `2222`) in Headquarters | Red form error: "The address or management port is outside the site's approved scope." | ☐ |
| AS-09 | **Add asset** in Security Lab: `127.0.0.1`, port `2222`, Collection **Linux · live SSH** | Error "An active asset already uses this endpoint." (`lab-ubuntu-01` already uses it) | ☐ |
| AS-10 | Click **Connect** on `ui-test-01` (10.20.5.20 doesn't exist) | Drawer "Connect ui-test-01" with step "1 · Confirm the device's host key". It shows "Reading the SSH host key…" for about 8 s, then "Could not open an SSH session to 10.20.5.20:22." and a **Try again** button. **Trust this key & connect** stays disabled | ☐ |
| AS-11 | Open `ui-test-01` and click **Archive asset**, then confirm the browser dialog | The row disappears and Overview's asset count drops | ☐ |
| AS-12 | **Connect / re-pin on the mock** (mock running). Open `lab-ubuntu-01`, click **Re-pin host key & credential** | Step 1 shows key type `ssh-rsa` and a `SHA256:…` fingerprint | ☐ |
| AS-13 | In a terminal, run `ssh-keygen -lf data\mock_ssh_host_rsa.key` | The `SHA256:…` part is identical to the UI value | ☐ |
| AS-14 | Enter Username `audituser`, Password `auditpass`, then click **Trust this key & connect** | It shows "Pinning…", then the toast "lab-ubuntu-01 connected — host key pinned". The drawer closes and the row still shows **Pinned** and **Scan** | ☐ |
| AS-15 | (Optional, needs a fresh endpoint) Create a site via **New site** (see 4.1) with CIDR `127.0.0.0/8` and port `2222`. Add a **Linux · live SSH** asset at `127.0.0.1:2222` in that site, then repeat AS-12 to AS-14 via **Connect** | It starts as **Not pinned**, then turns **Pinned** after trust, and the Action column shows **Scan** | ☐ |
| AS-16 | Click **Scan** on `core-sw-01` | All Scan buttons disable. Toast "Live scan completed — click the run below to see every check". **Last assessed** becomes "just now" | ☐ |
| AS-17 | Your PC row (**Windows · this machine**, chip **Live · this machine**). Click **Scan** | It completes. Compliance % updates. Some controls are UNKNOWN unless the API is elevated | ☐ |
| AS-18 | Stop `mock_targets.py`, then click **Scan** on `edge-fw-01` | Within seconds (FortiGate errors are not retried) the toast reads "Live scan partial — results updated", and the asset's controls show ERROR. The app stays usable. For `lab-ubuntu-01`, expect about 60 s first, because Linux SSH errors are retried after 20 s and then 40 s. Restart the mock afterwards | ☐ |

**CSV import.** "Insert sample" yields 3 valid rows for Headquarters (`app-03` 10.20.1.13, `edge-fw-02` 10.20.0.4, `access-sw-02` 10.20.0.12, all port 22). Archive the committed test assets afterwards.

Test CSV (two valid rows and one error row):
```
name,address,port,category,criticality,role
csv-web-01,10.20.5.11,22,linux,high,server
csv-web-02,10.20.5.12,22,linux,normal,server
csv-bad-01,10.20.5.13,8080,linux,high,server
```

| ID | Steps | Expected result | Pass/Fail |
|---|---|---|---|
| AS-19 | Click **Import CSV** | Drawer "Import assets from CSV", "Rows are validated first; nothing is saved until you commit." Fields: **Default site** select, a **CSV** textarea, **Insert sample**, **Validate rows** | ☐ |
| AS-20 | Click **Insert sample**, choose Default site = Headquarters, then **Validate rows** | The sample text fills in. Result "3 / 3 valid" and **Commit 3 assets** is enabled. Default adapters: linux → `linux-ssh`, firewall → `fortigate-ssh`, switch → `cisco-iosxe` | ☐ |
| AS-21 | Paste the test CSV, choose Headquarters, then **Validate rows** | The button shows "Validating…", then "**2 / 3 valid**" and **Commit 2 assets** is enabled. Under the count, the invalid row is listed as "Row 3 (csv-bad-01): Port 8080 is not in site approved ports: [22]." | ☐ |
| AS-22 | Click **Commit 2 assets** | The drawer closes and `csv-web-01` and `csv-web-02` appear with **Live · SSH** / **Not pinned**. Archive both test assets afterwards | ☐ |
| AS-23 | Validate with no Default site and no `site` column | 0 / N valid; each row lists "Target site is required or unresolvable." | ☐ |
| AS-24 | Validate the text `foo,bar` | Error: "CSV must contain at least 'name' and 'address' columns." | ☐ |

### 2.6 Assessments

| ID | Steps | Expected result | Pass/Fail |
|---|---|---|---|
| R-01 | Open Assessments as ava | Left: "Recent assessments" ("Auto-refreshing") with Run, State, Targets, Source and Created columns. Right: the **Live scan** panel (chip "Real-time collection") and the **Submit evidence** panel (chip "Offline import") | ☐ |
| R-02 | Live scan list | Each live asset has a checkbox. Mock devices show `· 127.0.0.1:2222` and your PC shows `· this machine`. Unready assets are greyed out with "connect on Assets". **Policy** reads `Enterprise Hardening Baseline (Multi-Platform) · rev N` | ☐ |
| R-03 | Untick everything except your PC, then click **Scan 1 asset now** | The button shows `Scanning… Queued/Running`. Toast "Live scan completed — click the run below to see every check". A new row "Live scan from console" appears with state COMPLETED, the target `<pc> NN% · N failed` and a Source chip | ☐ |
| R-04 | Tick all, then **Scan N assets now** (mock running) | All targets appear in one run. The Cisco, FortiGate and Ubuntu mocks each get a %. State COMPLETED (or PARTIAL if one failed) | ☐ |
| R-05 | Untick all | The button reads "Scan 0 assets now" and is disabled | ☐ |
| R-06 | **Submit evidence**: Target asset = `branch-rtr-01 — 10.20.10.1`, click **Sample: weak** | "Loaded **generated sample** · N facts" | ☐ |
| R-07 | Click **Evaluate evidence** | The button shows "Submitting…", then the toast "Evidence accepted — evaluation running". A new run appears within about 4 s, labeled import | ☐ |
| R-08 | Click **Sample: hardened** for the same asset and evaluate | branch-rtr-01's compliance goes up. Findings resolve, and Overview's recent activity shows "Fixed & verified" | ☐ |
| R-09 | Click **Upload JSON** and pick a non-JSON or random `.json` file | "That file is not a valid evidence bundle (JSON with a facts object)." | ☐ |
| R-10 | Clear the target asset | **Evaluate evidence** is disabled | ☐ |
| R-11 | Click any row in **Recent assessments** (or its name) | A panel opens with one section per asset: "N pass · N fail · N could not verify · N not applicable", the **Evidence digest** (`sha256` hex), and a table of every control with **Result**, **Control**, **Expected** and **Observed** (e.g. *Ensure VTY exec-timeout is 10 minutes or less* · `lte 600` · `1800`). Failures are listed first | ☐ |
| R-12 | In that panel tick **Show not-applicable controls** | Controls from other platforms' packs appear as Not applicable. Untick to hide them again. Close with ✕ or Esc | ☐ |

### 2.7 Findings

| ID | Steps | Expected result | Pass/Fail |
|---|---|---|---|
| F-01 | Open Findings | "N findings" count at top right. The state toggle defaults to **Open**. Severity: All / Critical / High / Medium / Low | ☐ |
| F-02 | Click **Accepted**, then **Resolved**, then **Open** | The list and URL `?state=` change. Accepted lists risk-accepted findings | ☐ |
| F-03 | Click **Critical** | Only CRITICAL chips remain. The URL has `severity=critical`. Click **All** to clear it | ☐ |
| F-04 | Type `ssh` in "Search by control, title or asset…" | Results filter on the server side | ☐ |
| F-05 | From Assets, click **Findings →** or **View findings** for an asset | The `<asset> ×` chip appears. Clicking it clears the filter | ☐ |
| F-06 | Filter so nothing matches | "No findings match these filters." | ☐ |
| F-07 | Click a row | Drawer: status chip (FAIL), severity, asset, title, and control key. **Expected (policy)** vs **Actual (device)** with the reason "Observed value violates the policy" | ☐ |
| F-08 | Evidence section | Live results show `reader_id`, "lines a–b" and `sha256:<16 hex>…` (hover shows the full hash). Imported results show "This result came from imported evidence without raw reader output." | ☐ |
| F-09 | Remediation | A summary, a code block of steps, and Verify / Authority / Impact. Click **Copy commands** and the label changes to **Copied** for 2 s; paste to confirm. Includes the note "Bastion never applies changes…" | ☐ |
| F-10 | History | Up to 8 events (opened, exception linked, …) with dates | ☐ |
| F-11 | "Risk exception" box | "Time-boxed; a different person must approve it." and **Request exception** (see 2.8) | ☐ |

### 2.8 Exceptions (dual custody)

The approve and reject actions need the `risk_approver` role (rowan only). Revoke needs `risk_approver` or `platform_admin`. The server refuses self-approval with "A requester cannot decide their own exception."

| ID | Steps | Expected result | Pass/Fail |
|---|---|---|---|
| E-01 | As **ava**: Findings → open an OPEN finding → **Request exception** | A form appears with "Business justification", "Compensating controls in place", and **Expires in** (7/30/60/90 days) | ☐ |
| E-02 | Enter a 5-character justification and submit | The browser blocks it (minimum 10 characters) | ☐ |
| E-03 | Fill both fields (10+ characters), choose 30 days, then **Submit for approval** | The form closes. The box now reads "An exception is requested (expires <date>)." and the button is gone | ☐ |
| E-04 | As ava, open **Exceptions** | The "Exception register" row shows state REQUESTED, requested by `ava.chen`, and "**Awaiting another approver**" with no Approve button | ☐ |
| E-05 | Sign out and sign in as **rowan**. Open Exceptions | The same row shows **Approve** and **Reject** | ☐ |
| E-06 | Click **Approve** | Toast "Exception approved". The state becomes APPROVED, with "approved by rowan.diaz" under the requester | ☐ |
| E-07 | Findings → **Accepted** | The finding is listed (state RISK_ACCEPTED). The Open count drops on Overview and in the nav badge | ☐ |
| E-08 | As rowan, click **Revoke** on the approved row | Toast "Exception revoked". The finding returns to **Open** | ☐ |
| E-09 | Self-approval: as **rowan** (rowan has analyst, so can request), request an exception on another finding, then open Exceptions | The row shows "Awaiting another approver" and **no Approve** for rowan. Note that ava has no risk_approver role, so **nobody in the demo org can approve a request made by rowan**. That is the intended outcome of dual custody here | ☐ |
| E-10 | As rowan, request and then **Reject** an ava request | Toast "Exception rejected". The state becomes REJECTED | ☐ |
| E-11 | Empty state (fresh org only) | "No exceptions – Request one from a finding’s detail panel." | ☐ |

### 2.9 Schedules

| ID | Steps | Expected result | Pass/Fail |
|---|---|---|---|
| SC-01 | Open Schedules as ava | Left: the "Schedules" table (Name, Cron, Next run, State) or "No schedules". Right: "New schedule" with Name, Site, Cron (default `0 2 * * *`), Time zone (default `UTC`) and **Create schedule** | ☐ |
| SC-02 | Name `UI test nightly`, Site Security Lab, keep the cron, Time zone `Asia/Kolkata`, then **Create schedule** | Toast "Schedule created". The row shows the cron, the time zone, the next run in the future, and **Enabled** | ☐ |
| SC-03 | Create the same name again | Error toast "That schedule name exists." | ☐ |
| SC-04 | Time zone `Mars/Base` or cron `99 * * * *` | Error toast (invalid schedule) | ☐ |
| SC-05 | Click **Pause**, then **Resume** | The chip flips between Paused and Enabled. Leave test schedules paused | ☐ |
| SC-06 | As rowan | "Read-only access – Your role cannot create schedules." No Pause/Resume buttons | ☐ |

### 2.10 Reports

| ID | Steps | Expected result | Pass/Fail |
|---|---|---|---|
| RP-01 | Open Reports as ava | "Generated reports" (Report, Scope, State, Digest) and "New report" with **Format** and **Evidence level** | ☐ |
| RP-02 | Format **PDF (text layout)**, Evidence level **Standard — all results**, then **Generate report** | "Rendering…", then the toast "Report generated from the latest results". The new row reads **PDF**, `N assets · M results`, policy name · Standard, COMPLETED, and a 12-character digest… | ☐ |
| RP-03 | Click **Download** | A PDF downloads and opens with the asset and result tables | ☐ |
| RP-04 | Repeat with **Self-contained HTML**, **CSV (spreadsheet-safe)** and **JSON (machine-readable)**, and with **Summary** and **Full** levels | Each file downloads and opens. Summary contains only failures and unresolved results | ☐ |
| RP-05 | As rowan (analyst) | Can generate and download | ☐ |
| RP-06 | Fresh org with no results | Error toast "No completed assessment results are available for this scope." | ☐ |

### 2.11 Policies

| ID | Steps | Expected result | Pass/Fail |
|---|---|---|---|
| P-01 | Open Policies | "Policy revisions" (Name, Revision, State, Digest), "Drafts awaiting approval" ("Two-person publish"), "New draft", and the "Controls" table (Severity, Control, Origin, Passing, Failing, Plan **Reviewed**/**None**) with "N controls · latest results across assets" | ☐ |
| P-02 | As ava, in **New draft**: Name `UI test draft`, tick one excluded control, Reason `Testing the two-person publish flow`, then **Create draft** | Toast "Draft created — a different approver must publish it". The draft appears with REQUESTED, "1 exclusions" and the chip **Needs another approver** (ava is not a policy_approver) | ☐ |
| P-03 | Click **Preview Impact** on the draft | Drawer "Policy Impact Preview: UI test draft" with chips "N Total Active Assets" and "N Flipping to Pass/N.A.", plus a table of affected controls or "No Status Changes" | ☐ |
| P-04 | Sign in as **rowan** within 5 minutes, open Policies | The draft shows a **Publish** button | ☐ |
| P-05 | Click **Publish** | Toast "Policy published". The draft leaves the list and a new revision appears as published | ☐ |
| P-06 | Click Publish more than 5 minutes after signing in | Error toast "Sign in with MFA again before performing this action." Sign out and in again, then retry | ☐ |
| P-07 | As rowan, check **New draft** | "Read-only access – Your role cannot author policies." | ☐ |

> ⚠️ Publishing changes which policy scans use. The console picks the published policy with the **most rule packs**, newest first. A new draft includes all approved packs, so once published it becomes the active policy, **including its exclusions**. Before the demo, either don't publish test drafts, or publish one with no exclusions. Check **Live scan → Policy** on Assessments.

### 2.12 Role-based access: ava vs rowan

| ID | Area | ava sees | rowan sees | Pass/Fail |
|---|---|---|---|---|
| RB-01 | Assets header | **Scan all live**, **Import CSV**, **Add asset** | None of them | ☐ |
| RB-02 | Assets row action / drawer | Scan, Connect, Re-pin, Archive | Only **Findings →** / **View findings** | ☐ |
| RB-03 | Assessments right column | Live scan and Submit evidence | "Read-only access – Your role cannot submit evidence. Ask an administrator for the scan operator role." | ☐ |
| RB-04 | Findings drawer | Request exception | Request exception (analyst) | ☐ |
| RB-05 | Exceptions | Revoke only (no Approve/Reject) | Approve / Reject (others' requests), Revoke | ☐ |
| RB-06 | Schedules | Create, Pause/Resume | Read-only | ☐ |
| RB-07 | Reports | Generate | Generate | ☐ |
| RB-08 | Policies | Create draft, never Publish | Publish (others' drafts), no Create | ☐ |
| RB-09 | Sites (**New site**) | Allowed (platform_admin) | Not allowed | ☐ |

### 2.13 Error and empty states

| ID | Steps | Expected result | Pass/Fail |
|---|---|---|---|
| ER-01 | Stop the API while signed in and wait about 30 s | Sidebar footer shows "API unavailable" (grey dot). Pages fail with "The request could not be completed …" plus a Reference ID | ☐ |
| ER-02 | Reload with the API down | "Overview – The control API is unavailable." with an error notice | ☐ |
| ER-03 | Restart the API and reload | Back to normal. The session survives the restart (12 h) | ☐ |
| ER-04 | Live scan with the mock stopped | Covered in AS-18: failed/partial toast, no crash | ☐ |
| ER-05 | Empty-state texts (fresh org) | Overview "No assessment results yet" with **Start first assessment**. Assessments "No assessments yet". Reports "No reports yet". Schedules "No schedules". Policies "No drafts" | ☐ |
| ER-06 | Sign in with demo login disabled (`BG_DEMO_LOGIN=false` plus an API restart) | "Quick demo access" and **Auto-fill demo code** are hidden. Only the password + MFA path works | ☐ |

### 2.14 Responsive / narrow viewport

Use DevTools device mode at 390 × 844 (iPhone 12) and 768 px.

| ID | Steps | Expected result | Pass/Fail |
|---|---|---|---|
| RS-01 | Landing at 390 px | The nav collapses to the logo plus **Open console** (Sign in is hidden below 560 px). Sections stack into one column. No horizontal scroll | ☐ |
| RS-02 | Sign-in at 390 px | The brand panel shrinks (the audit stream is hidden). The form is full width. The six OTP boxes fit | ☐ |
| RS-03 | Docs at 390 px | The sidebar is hidden and the content is readable | ☐ |
| RS-04 | Console at 760 px or narrower | The sidebar stacks above the content (no fixed left rail). The search pill is hidden below 640 px, but **Ctrl+K** still works | ☐ |
| RS-05 | Overview at 390 px | KPIs and platform cards go to one column. The charts stay visible | ☐ |
| RS-06 | Assets / Findings tables at 390 px | Tables scroll horizontally inside their cards. Drawers open full width and **Close** is reachable | ☐ |

---

## 3. Live proof: flip a real Windows setting

This scenario shows a real verdict changing on this PC. The control is **`org.win.scr.is_secure` – "Ensure 'Password protect the screen saver' is enabled"** (medium). Bastion reads `HKCU:\Control Panel\Desktop\ScreenSaverIsSecure`. A missing value counts as `0` (FAIL), and `1` is a PASS.

Why this control:
- It is per-user (HKCU), so you don't need admin rights.
- It has no security downside.
- It is reversible in one command.

> The API must run as the **same Windows user** you change the setting for, since HKCU is per-user.

1. **Record the current value** (PowerShell):
   ```powershell
   Get-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name ScreenSaverIsSecure -ErrorAction SilentlyContinue
   ```
   Note whether it prints a value, and what it is. On this PC it was **absent** when this guide was written, which means FAIL.
2. **Baseline scan.** Assets → your PC row (**Live · this machine**) → **Scan**. Wait for the toast.
3. Findings → state **Open**, search `screen saver`. You should see "Ensure 'Password protect the screen saver' is enabled" on your PC. In the drawer: Expected `Is secure = 1`, Actual `Is secure = 0`, "Observed value violates the policy".
4. **Change the setting:**
   ```powershell
   Set-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name ScreenSaverIsSecure -Value '1'
   ```
   (GUI equivalent: Settings → Personalization → Lock screen → Screen saver → tick "On resume, display logon screen".)
5. **Rescan** the PC from Assets (or Assessments → Live scan, with only the PC ticked).
6. **Verify the flip:**
   - The finding is no longer under **Open**. It now appears under **Resolved**.
   - Overview → Recent activity shows "Fixed & verified" for your PC.
   - The PC's compliance % goes up.
   - Policies → that control's Passing count goes up by 1.
7. **Revert** to the value you recorded in step 1:
   ```powershell
   # If it was ABSENT originally:
   Remove-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name ScreenSaverIsSecure
   # If it was '0' originally:
   Set-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name ScreenSaverIsSecure -Value '0'
   ```
   (GUI: untick "On resume, display logon screen".)
8. **Rescan.** The finding is OPEN again (Recent activity may show "Reopened"), which proves the check works in both directions.

If the value was already `1` on demo day, run the same steps in reverse: set it to `'0'`, see the result go to FAIL, then set it back to `'1'`.

---

## 4. Ubuntu lab device (real SSH host)

Prepare the box first using **`docs/runbooks/ubuntu-lab-onboarding.md`**. In short, `sudo bash tools/ubuntu_lab_setup.sh [audituser]` installs OpenSSH and auditd, creates the audit account, adds a sudoers rule for exactly `/usr/sbin/sshd -T`, and prints the IP and host-key fingerprints. You can preflight from Windows:
```powershell
.\.venv\Scripts\python.exe tools/check_ubuntu_target.py <ubuntu-ip> --user audituser
```
The Connect form only accepts a **password**. If the box has `PasswordAuthentication no`, enable passwords for just the audit user, as the setup script prints: a `Match User` block in `/etc/ssh/sshd_config.d/90-bastion.conf`, followed by `systemctl reload ssh`.

### 4.1 UI steps

| ID | Steps | Expected result | Pass/Fail |
|---|---|---|---|
| U-01 | As ava, Assets → **New site**. Enter a name (e.g. `Ubuntu Lab`), a timezone (IANA, e.g. `Asia/Kolkata`), allowed networks as CIDR (e.g. `192.168.1.0/24`, or `<ip>/32`), and allowed ports `22`. Save | The site is created. It appears in the **Site** list of **Add asset** and **Import CSV**. An invalid timezone or empty CIDR/port list is rejected by the API ("timezone must be a valid IANA timezone", etc.) | ☐ |
| U-02 | **Add asset**: Site `Ubuntu Lab`, Name `ubuntu-lab-01`, Address `<ubuntu-ip>`, Port `22`, Category **Linux server**, Collection **Linux · live SSH**, Role `server`, Criticality `high` | The row appears with **Live · SSH**, **Not pinned** and **Connect**. Platform shows `linux` until the first scan | ☐ |
| U-03 | Click **Connect** | Step 1 shows the key type (e.g. `ssh-ed25519`) and `SHA256:…` | ☐ |
| U-04 | On the Ubuntu box: `for f in /etc/ssh/ssh_host_*_key.pub; do ssh-keygen -lf "$f"; done` | The line with the **same key type** (ED25519 / ECDSA / RSA) has the identical `SHA256:…`. If it doesn't match, **do not trust the key** | ☐ |
| U-05 | Username `audituser`, the password you set, then **Trust this key & connect** | Toast "ubuntu-lab-01 connected — host key pinned". The row shows **Pinned** and **Scan**. Note: Connect does **not** test the password. A wrong password only shows up as a failed scan | ☐ |
| U-06 | Click **Scan** | Toast "Live scan completed …". Compliance % appears. Findings for `ubuntu-lab-01` show live evidence (`reader_id`, sha256) | ☐ |

### 4.2 Flip test: PermitRootLogin

The control is **`org.linux.ubuntu22.auth_ssh_permit_root_login` – "Disable direct SSH login for the root account"** (high). Its assertion is that `sshd -T` reports `permitrootlogin` **= `no`**.

> Ubuntu's default is `prohibit-password`, which `sshd -T` prints as `without-password`. Bastion normalizes that to `prohibit-password`. It is not `no`, so a stock box gives a real **FAIL**. For a clean PASS↔FAIL flip, switch the same file between `no` and `yes`, as shown below. Before each scan, confirm the effective value with `sudo sshd -T | grep -i permitrootlogin`. Drop-ins are read in name order and the first value wins, so make sure no earlier file in `/etc/ssh/sshd_config.d/` already sets PermitRootLogin.

| ID | Steps (on the Ubuntu box, then in the UI) | Expected result | Pass/Fail |
|---|---|---|---|
| U-07 | `echo "PermitRootLogin no" \| sudo tee /etc/ssh/sshd_config.d/99-demo.conf && sudo systemctl reload ssh`, then **Scan** `ubuntu-lab-01` | The control is PASS. The finding is absent from Open, or appears under **Resolved** | ☐ |
| U-08 | `echo "PermitRootLogin yes" \| sudo tee /etc/ssh/sshd_config.d/99-demo.conf && sudo systemctl reload ssh`, then **Scan** | **FAIL**. Findings → Open shows "Disable direct SSH login for the root account" with Expected `Permit root login = no` and Actual `Permit root login = yes` | ☐ |
| U-09 | Switch back to `no` (U-07), then **Scan** | **PASS** again. The finding moves to Resolved and Overview shows "Fixed & verified" | ☐ |
| U-10 | Clean up: `sudo rm /etc/ssh/sshd_config.d/99-demo.conf && sudo systemctl reload ssh`, then **Scan** | Back to the Ubuntu default (`without-password` → `prohibit-password`). Expect **FAIL** with Actual `prohibit-password` | ☐ |

For comparison, the mock `lab-ubuntu-01` always reports `permitrootlogin no`, so it is PASS for this control.

---

## 5. Known issues

These come from reading the code as of 2026-10-30. Avoid them during the demo.

1. **CSV Windows rows become "Live · this machine".** The default adapter for `windows` is `windows-local` (`inventory.py:443`). Scanning such a row audits the API host, not the address in the CSV.
2. **No assessment run detail and no visible digest.** Run rows aren't clickable, and `targets[].digest` from the API is never rendered (`apps/web/src/pages/Assessments.tsx:26-34`). Show digests via the Findings drawer or Reports instead.
3. **Command palette shortcut hints don't work.** The "G O", "G A", "G F", "G S", "G P" and "G R" hints are displayed (`apps/web/src/App.tsx:263-283`), but only Ctrl/⌘+K is handled (`App.tsx:82-91`). The palette also has no Exceptions or Schedules entries.
4. **Unreachable "Return to Console" branch.** `/landing` returns early (`App.tsx:109-111`), so the "Return to Console" label (`App.tsx:200-202`), the "Product Overview" crumb (`App.tsx:181`) and the `/landing` route inside the shell (`App.tsx:226`) can never render.
5. **Offline-import samples for new assets default to Ubuntu.** Assets added through the UI have no `identity`, so the sample request falls back to `family=ubuntu` even for Windows or Cisco assets (`Assessments.tsx:136`). Most controls then come back N/A.
6. **Shared cache key with different limits.** `ImportPanel` and `LiveScanPanel` both use the query key `["assets","list"]`, with `limit=100` and `limit=200` respectively (`Assessments.tsx:56` vs `:124`, which also matches `Assets.tsx:71`). Whichever fetch runs first fills the cache.
7. **UI and API disagree on who can scan.** The UI shows Scan for `platform_admin` (`Assets.tsx:121`, `Assessments.tsx:11`), but the API requires `scan_operator` (`apps/api/src/baselineguard_api/routes/v1/scans.py:60`). This is harmless for ava, who has both roles.
8. **Connect doesn't verify the credential.** `routes/v1/live.py` (connect) pins the key and stores the password without a test login. A typo only surfaces as a failed scan.
9. **Demo login satisfies "recent MFA".** `_open_session` sets `mfa_verified_at` for `demo-password-only` sessions (`routes/v1/auth.py`, `_open_session`), so `require_recent_mfa` for policy publish (`routes/v1/policies.py:445`) passes without MFA. This is acceptable for the demo, but worth knowing.
10. **Schedules and scans may pick different policies.** Schedules uses the *first* published policy from `/policy-overview` (`apps/web/src/pages/Schedules.tsx:19`), while scans use the published policy with the most packs (`apps/web/src/lib/hooks.ts:17-31`). The form also doesn't reset after a successful create.
11. **Single-approver demo org.** Only rowan has `risk_approver` and only rowan has `policy_approver`. Exceptions requested by rowan, and drafts authored by rowan (rowan can't author), can never be decided. This is by design, but don't demo "rowan requests" expecting an approval.

Fixed on 2026-10-30 (no longer need workarounds): CSV `tags` type, "Insert sample" validity, per-row CSV errors, CSV category list, Assets load-error notice, the "rejectd" toast typo, and the Docs page button label (now **Continue**). See `docs/development/project-status.md`.
