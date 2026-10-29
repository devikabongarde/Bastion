"""Local identity, MFA challenges, scoped roles and revocable sessions.

Revision ID: 0003_local_identity
Revises: 0002_job_cancellation
"""

from typing import Any

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql as pg

revision = "0003_local_identity"
down_revision = "0002_job_cancellation"
branch_labels = None
depends_on = None


def timestamps() -> list[sa.Column[Any]]:
    return [
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column("row_version", sa.BigInteger, server_default="1", nullable=False),
    ]


def scoped(table):
    predicate = "org_id = nullif(current_setting('app.org_id', true), '')::uuid"
    op.execute(f'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY')
    op.execute(f'ALTER TABLE "{table}" FORCE ROW LEVEL SECURITY')
    op.execute(
        f'CREATE POLICY "{table}_org_isolation" ON "{table}" '
        f"USING ({predicate}) WITH CHECK ({predicate})"
    )


def upgrade():
    op.create_table(
        "users",
        sa.Column("id", pg.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "org_id", pg.UUID(as_uuid=True), sa.ForeignKey("organizations.id"), nullable=False
        ),
        sa.Column("subject", sa.String(255), nullable=False),
        sa.Column("auth_provider", sa.String(24), nullable=False),
        sa.Column("email", sa.String(320), nullable=False),
        sa.Column("password_hash", sa.String(512)),
        sa.Column("totp_ciphertext", sa.LargeBinary),
        sa.Column("last_totp_step", sa.BigInteger, nullable=False, server_default="-1"),
        sa.Column("recovery_hashes", pg.JSONB, nullable=False, server_default="[]"),
        sa.Column("disabled_at", sa.DateTime(timezone=True)),
        *timestamps(),
        sa.UniqueConstraint("org_id", "id", name="uq_users_org_id"),
        sa.UniqueConstraint("org_id", "auth_provider", "subject", name="uq_users_subject"),
    )
    scoped("users")
    op.create_table(
        "role_bindings",
        sa.Column("id", pg.UUID(as_uuid=True), primary_key=True),
        sa.Column("org_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("user_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("role", sa.String(40), nullable=False),
        sa.Column("site_id", pg.UUID(as_uuid=True)),
        *timestamps(),
        sa.ForeignKeyConstraint(["org_id", "user_id"], ["users.org_id", "users.id"]),
        sa.ForeignKeyConstraint(["org_id", "site_id"], ["sites.org_id", "sites.id"]),
        sa.UniqueConstraint(
            "org_id",
            "user_id",
            "role",
            "site_id",
            name="uq_role_bindings_scope",
            postgresql_nulls_not_distinct=True,
        ),
        sa.CheckConstraint(
            "role IN ('viewer','analyst','scan_operator','auditor','manual_assessor',"
            "'policy_author','policy_approver','risk_approver','credential_admin',"
            "'platform_admin','inventory_editor')",
            name="ck_role_bindings_role",
        ),
        sa.CheckConstraint("role <> 'platform_admin' OR site_id IS NULL", name="ck_admin_scope"),
    )
    scoped("role_bindings")
    for table in ("sessions", "auth_challenges"):
        extra: list[Any] = (
            [
                sa.Column("mfa_verified_at", sa.DateTime(timezone=True), nullable=False),
                sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
                sa.Column("revoked_at", sa.DateTime(timezone=True)),
            ]
            if table == "sessions"
            else [
                sa.Column("attempts", sa.Integer, nullable=False, server_default="0"),
                sa.Column("consumed_at", sa.DateTime(timezone=True)),
                sa.CheckConstraint("attempts BETWEEN 0 AND 5", name="ck_challenge_attempts"),
            ]
        )
        op.create_table(
            table,
            sa.Column("id", pg.UUID(as_uuid=True), primary_key=True),
            sa.Column("org_id", pg.UUID(as_uuid=True), nullable=False),
            sa.Column("user_id", pg.UUID(as_uuid=True), nullable=False),
            sa.Column("token_hash", sa.LargeBinary, unique=True, nullable=False),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
            *extra,
            sa.ForeignKeyConstraint(["org_id", "user_id"], ["users.org_id", "users.id"]),
        )
        op.create_index(f"ix_{table}_expiration", table, ["expires_at"])
        scoped(table)
    # Infrastructure throttle keys are keyed hashes, with no account/source plaintext.
    op.create_table(
        "auth_throttles",
        sa.Column("key_hash", sa.String(64), primary_key=True),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("attempts", sa.Integer, nullable=False),
    )
    op.execute("""
    DO $$ BEGIN
      IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'bg_api') THEN
        GRANT SELECT (id, slug, status) ON organizations TO bg_api;
        GRANT SELECT, UPDATE ON users TO bg_api;
        GRANT SELECT ON role_bindings TO bg_api;
        GRANT SELECT, INSERT, UPDATE, DELETE ON sessions, auth_challenges, auth_throttles TO bg_api;
      END IF;
    END $$
    """)


def downgrade():
    for table in ("auth_throttles", "auth_challenges", "sessions", "role_bindings", "users"):
        op.drop_table(table)
