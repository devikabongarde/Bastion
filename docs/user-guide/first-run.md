# First run: using the console

This guide assumes the stack is running: the API on `http://127.0.0.1:8000` with embedded workers, and the web console on `http://127.0.0.1:5173`. It also assumes the demo data has been seeded. If not, follow [local setup](../development/local-setup.md).

## 1. Landing page → console

1. Open **http://127.0.0.1:5173/**. Signed-out visitors see the **landing page**. The in-app documentation is at `/docs`.
2. Click **Open console** (or **Sign in**). This goes to **`/login`**.

## 2. Sign in

| Field | Value |
|---|---|
| Organization | `northwind` |
| Username | `ava` (administrator: platform_admin, scan_operator, analyst, auditor, policy_author, inventory_editor, viewer, manual_assessor) or `rowan` (risk_approver, policy_approver, analyst, viewer) |
| Password | `BaselineGuard-Demo-2026` on the demo machine (pre-filled; see `USER_MANUAL.md`). A freshly seeded database uses a random password stored in `data/demo-credentials.json`. |

There are three ways to sign in:

- **Normal (with MFA).** Click **Continue**, then enter the 6-digit authenticator code. Get the current codes from `.\.venv\Scripts\python.exe tools/totp.py`. A one-time recovery code also works when the account has them.
- **Auto-fill demo code.** When `BG_DEMO_LOGIN=true`, the verify step offers this button. It fetches the current code from `/auth/demo-code` and signs you in.
- **Quick demo access.** When `BG_DEMO_LOGIN=true`, the sign-in page shows one-click buttons for `ava` and `rowan`. These skip MFA, still check the password, and are recorded in the audit log as `demo-password-only`.

The session lasts 12 hours and ends after 30 minutes idle. The sign-in rate limit is 20 attempts per account per 15 minutes.

## 3. Find your way around

| Page | Path | What you can do |
|---|---|---|
| Overview | `/` | Fleet compliance and evidence completeness, open findings by severity, per-asset posture and freshness |
| Assets | `/assets` | List and filter assets. **New site** (platform_admin), **Add asset**, **Import CSV**, **Connect** (pin host key + credential), **Scan** / **Scan all live**, archive. |
| Assessments | `/assessments` | Scan runs, per-target state, compliance %, result digest |
| Findings | `/findings` | Filter by state, severity or asset. The detail drawer shows expected vs. actual values, evidence, remediation, history, assignment and due date. You can also request an exception. Manual review and drift comparison are API-only (`POST /findings/{id}/review`, `GET /assets/{id}/drift`). |
| Exceptions | `/exceptions` | Requested, approved, rejected, revoked and expired exceptions. Approve, reject or revoke them as a risk approver. |
| Schedules | `/schedules` | Cron schedules per site (live assets only), enable or disable |
| Reports | `/reports` | Generate and download JSON, HTML, CSV or PDF reports |
| Policies | `/policies` | Published policy and controls. Create, edit and preview drafts; publish as an independent approver. |

**Ctrl/⌘+K** opens a command palette for quick navigation. The "G O / G A …" shortcut hints in it are labels only; they are not bound to keys. The console has light and dark themes.

## 4. First tasks

1. **Look at the results.** Overview → click an asset → **View findings**.
2. **Run a live scan.** Assets → **Scan all live**. This requires the mock devices (`tools/mock_targets.py`) and `BG_LAB_TARGETS=true`. Watch Assessments update.
3. **Onboard a new live device.** Add a site and an asset, then use **Connect**: compare the fingerprint and enter the read-only credential. Then click **Scan**. The [Ubuntu lab runbook](../runbooks/ubuntu-lab-onboarding.md) walks through this.
4. **Exception workflow.**
   1. As `ava`, open a failing finding and request an exception (reason, compensating controls, expiry).
   2. Sign out, then sign in as `rowan`.
   3. Go to **Exceptions** and approve it. The finding becomes `RISK_ACCEPTED`.

   A user cannot approve their own request.
5. **Report.** Reports → choose a format → download. Each download is recorded in the audit log.

## 5. Shutting down

Stop the web and API processes (Ctrl+C), then run `docker compose -f deploy/compose/compose.yaml stop`. This keeps the database volume. `down -v` deletes all data.
