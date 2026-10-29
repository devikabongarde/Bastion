"""Durable cooperative cancellation for leased collection jobs.

Revision ID: 0002_job_cancellation
Revises: 0001_phase1_core
"""

import sqlalchemy as sa
from alembic import op

revision = "0002_job_cancellation"
down_revision = "0001_phase1_core"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("jobs", sa.Column("cancel_requested_at", sa.DateTime(timezone=True)))


def downgrade() -> None:
    op.drop_column("jobs", "cancel_requested_at")
