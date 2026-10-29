"""Allow the application role to update exception approval state.

Revision ID: 0005_exception_workflow
Revises: 0004_pipeline
"""

from alembic import op

revision = "0005_exception_workflow"
down_revision = "0004_pipeline"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
    DO $$
    BEGIN
      IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'bg_api') THEN
        EXECUTE 'GRANT UPDATE ON exceptions TO bg_api';
      END IF;
    END
    $$""")


def downgrade() -> None:
    op.execute("""
    DO $$
    BEGIN
      IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'bg_api') THEN
        EXECUTE 'REVOKE UPDATE ON exceptions FROM bg_api';
      END IF;
    END
    $$""")
