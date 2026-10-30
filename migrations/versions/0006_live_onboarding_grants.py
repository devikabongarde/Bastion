"""Grants for live-collection onboarding (host-key pinning + credential binding).

The API connects as the least-privilege `bg_api` role. Onboarding a live SSH device
needs exactly two more privileges, still confined per organization by row-level security:

* UPDATE on asset_trust  - revoke the previous pin when a host key is re-pinned
* INSERT on credentials  - store the sealed (encrypted) audit credential
"""

from alembic import op

revision = "0006_live_onboarding_grants"
down_revision = "0005_exception_workflow"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
    DO $$
    BEGIN
      IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'bg_api') THEN
        EXECUTE 'GRANT UPDATE ON asset_trust TO bg_api';
        EXECUTE 'GRANT INSERT ON credentials TO bg_api';
      END IF;
    END
    $$""")


def downgrade() -> None:
    op.execute("""
    DO $$
    BEGIN
      IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'bg_api') THEN
        EXECUTE 'REVOKE UPDATE ON asset_trust FROM bg_api';
        EXECUTE 'REVOKE INSERT ON credentials FROM bg_api';
      END IF;
    END
    $$""")
