# First run (development)

This guide covers the current development build. It is not a production deployment guide. The deployment and recovery release gates remain pending.

## 1. Prepare local secrets and PostgreSQL

Copy `.env.example` to `.env`. Replace the three database password placeholders with independent random secrets, update both PostgreSQL URLs to match, and set a random `BG_SESSION_SECRET` of at least 32 characters. Keep `.env` out of Git and never paste credentials into a ticket or terminal transcript. Start Docker Desktop, then run the development commands in the repository README. Confirm PostgreSQL is healthy before running Alembic.

The migration role is for schema changes; the API must connect as the non-owner `bg_api` runtime role. Do not use the superuser or migration role in the API. Database initialization scripts run only when the PostgreSQL data directory is first created.

## 2. Bootstrap one local administrator

From the repository root, run:

```powershell
uv run python -m baselineguard_api.bootstrap --organization local --name "Local Organization" --username admin --email admin@example.invalid --roles platform_admin,inventory_editor,scan_operator,policy_author,policy_approver,credential_admin,risk_approver
```

The bootstrap asks for a password and authenticator code interactively; it does not accept passwords as arguments. Use a real email address only if appropriate for your local account record. The bootstrap writes the local master key if absent, displays the TOTP enrollment secret/URI and one-time recovery codes, and assigns the requested roles. Put the master key and recovery codes in the organization's approved secret store; the application intentionally cannot reveal them later. Protect the `data/keys` directory with user-only access.

The local bootstrap is an administrative operation. Do not expose it as a network endpoint or run it against a production database without an approved provisioning procedure.

## 3. Sign in and add scoped inventory

Open the Vite development URL, sign in with the provisioned account, and complete the authenticator challenge. Add a site with its timezone and explicit allowed CIDRs, DNS suffixes, and management ports through the API. Add only authorized assets whose address and port fall within that site scope. Use unique idempotency keys for create requests. The inventory UI currently lists assets; create/update and complete inventory administration are not yet delivered as GUI workflows.

## 4. Policies and scans: current limitation

Policy draft creation requires an approved rule pack in the organization's database; publication requires a different user holding the policy approver role and recent MFA. This build does not yet include the complete pack import/approval workflow or scan worker pipeline. A scan request is queued but is not evidence that a collection or evaluation completed. Do not interpret `QUEUED` or an empty findings page as a clean assessment.

## 5. Local shutdown and data handling

Stop the API and frontend processes, then stop the local database with `docker compose -f deploy/compose/compose.yaml stop`. This retains the database volume. Do not delete the volume unless intentionally destroying all local state. Evidence storage, encrypted credential lifecycle, backup/restore, and retention workflows are not release-qualified yet.
