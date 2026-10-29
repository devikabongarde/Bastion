"""Phase 1 core inventory, policy, job, audit and RLS foundation.

Revision ID: 0001_phase1_core
Revises:
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0001_phase1_core"
down_revision = None
branch_labels = None
depends_on = None


def _org_policy(table: str) -> None:
    policy = f"{table}_org_isolation"
    predicate = "org_id = nullif(current_setting('app.org_id', true), '')::uuid"
    op.execute(f'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY')
    op.execute(f'ALTER TABLE "{table}" FORCE ROW LEVEL SECURITY')
    op.execute(
        f'CREATE POLICY "{policy}" ON "{table}" USING ({predicate}) WITH CHECK ({predicate})'
    )


def upgrade() -> None:
    # PostgreSQL 17+ only; application roles must be separate NOBYPASSRLS roles.
    op.create_table(
        "organizations",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("slug", sa.String(100), nullable=False, unique=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column(
            "settings", postgresql.JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")
        ),
        sa.Column("status", sa.String(24), nullable=False, server_default="active"),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column("row_version", sa.BigInteger, nullable=False, server_default="1"),
        sa.CheckConstraint(
            "status IN ('active', 'suspended', 'archived')", name="ck_organizations_status"
        ),
    )
    op.create_table(
        "sites",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "org_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organizations.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("timezone", sa.String(100), nullable=False),
        sa.Column("scope", postgresql.JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column("row_version", sa.BigInteger, nullable=False, server_default="1"),
        sa.UniqueConstraint("org_id", "id", name="uq_sites_org_id"),
        sa.UniqueConstraint("org_id", "name", name="uq_sites_org_name"),
    )
    op.create_index("ix_sites_org", "sites", ["org_id"])
    _org_policy("sites")

    op.create_table(
        "assets",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("org_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("site_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("category", sa.String(24), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("address", sa.String(253), nullable=False),
        sa.Column("port", sa.Integer, nullable=False),
        sa.Column("adapter_id", sa.String(100), nullable=False),
        sa.Column("declared_role", sa.String(100), nullable=False),
        sa.Column("identity", postgresql.JSONB),
        sa.Column("criticality", sa.String(16), nullable=False, server_default="normal"),
        sa.Column("owner_id", postgresql.UUID(as_uuid=True)),
        sa.Column("tags", postgresql.JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("archived_at", sa.DateTime(timezone=True)),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column("row_version", sa.BigInteger, nullable=False, server_default="1"),
        sa.UniqueConstraint("org_id", "id", name="uq_assets_org_id"),
        sa.ForeignKeyConstraint(
            ["org_id", "site_id"], ["sites.org_id", "sites.id"], ondelete="RESTRICT"
        ),
        sa.CheckConstraint(
            "category IN ('windows', 'linux', 'firewall', 'router', 'switch')",
            name="ck_assets_category",
        ),
        sa.CheckConstraint(
            "criticality IN ('critical', 'high', 'normal', 'low')", name="ck_assets_criticality"
        ),
        sa.CheckConstraint("port BETWEEN 1 AND 65535", name="ck_assets_port"),
    )
    op.create_index("ix_assets_org_site_category", "assets", ["org_id", "site_id", "category"])
    op.create_index("ix_assets_org_updated", "assets", ["org_id", "updated_at"])
    op.create_index(
        "uq_assets_active_endpoint",
        "assets",
        ["org_id", "site_id", "address", "port", "adapter_id"],
        unique=True,
        postgresql_where=sa.text("archived_at IS NULL"),
    )
    _org_policy("assets")

    op.create_table(
        "rule_packs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "org_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organizations.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("pack_key", sa.String(200), nullable=False),
        sa.Column("version", sa.String(64), nullable=False),
        sa.Column("digest", sa.String(64), nullable=False),
        sa.Column("manifest", postgresql.JSONB, nullable=False),
        sa.Column("rights_metadata", postgresql.JSONB, nullable=False),
        sa.Column("state", sa.String(24), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column("row_version", sa.BigInteger, nullable=False, server_default="1"),
        sa.UniqueConstraint("org_id", "id", name="uq_rule_packs_org_id"),
        sa.UniqueConstraint("org_id", "pack_key", "version", name="uq_rule_packs_version"),
        sa.CheckConstraint("state IN ('draft', 'approved', 'revoked')", name="ck_rule_packs_state"),
        sa.CheckConstraint("digest ~ '^[0-9a-f]{64}$'", name="ck_rule_packs_digest"),
    )
    op.create_index("ix_rule_packs_org_state", "rule_packs", ["org_id", "state"])
    _org_policy("rule_packs")

    op.create_table(
        "policies",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "org_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organizations.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("revision", sa.Integer, nullable=False),
        sa.Column("spec", postgresql.JSONB, nullable=False),
        sa.Column("digest", sa.String(64), nullable=False),
        sa.Column("state", sa.String(24), nullable=False),
        sa.Column("author_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("approver_id", postgresql.UUID(as_uuid=True)),
        sa.Column("published_at", sa.DateTime(timezone=True)),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column("row_version", sa.BigInteger, nullable=False, server_default="1"),
        sa.UniqueConstraint("org_id", "id", name="uq_policies_org_id"),
        sa.UniqueConstraint("org_id", "name", "revision", name="uq_policies_revision"),
        sa.CheckConstraint("revision > 0", name="ck_policies_revision"),
        sa.CheckConstraint("state IN ('draft', 'published', 'revoked')", name="ck_policies_state"),
        sa.CheckConstraint("digest ~ '^[0-9a-f]{64}$'", name="ck_policies_digest"),
        sa.CheckConstraint(
            "state <> 'published' OR (approver_id IS NOT NULL "
            "AND approver_id <> author_id AND published_at IS NOT NULL)",
            name="ck_policies_two_person_publish",
        ),
    )
    op.create_index("ix_policies_org_state", "policies", ["org_id", "state"])
    _org_policy("policies")

    op.create_table(
        "policy_pack_links",
        sa.Column("org_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("policy_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("rule_pack_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("pack_digest", sa.String(64), nullable=False),
        sa.ForeignKeyConstraint(
            ["org_id", "policy_id"], ["policies.org_id", "policies.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["org_id", "rule_pack_id"], ["rule_packs.org_id", "rule_packs.id"], ondelete="RESTRICT"
        ),
    )
    _org_policy("policy_pack_links")

    op.create_table(
        "scan_runs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("org_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("policy_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("requester_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("reason", sa.String(500), nullable=False),
        sa.Column("scope_manifest", postgresql.JSONB, nullable=False),
        sa.Column("status", sa.String(24), nullable=False, server_default="QUEUED"),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("finished_at", sa.DateTime(timezone=True)),
        sa.UniqueConstraint("org_id", "id", name="uq_scan_runs_org_id"),
        sa.ForeignKeyConstraint(
            ["org_id", "policy_id"], ["policies.org_id", "policies.id"], ondelete="RESTRICT"
        ),
        sa.CheckConstraint(
            "status IN ('QUEUED', 'PREFLIGHT', 'COLLECTING', 'NORMALIZING', "
            "'EVALUATING', 'RETRY_WAIT', 'COMPLETED', 'PARTIAL', 'FAILED', 'CANCELLED')",
            name="ck_scan_runs_status",
        ),
    )
    op.create_index("ix_scan_runs_org_created", "scan_runs", ["org_id", "created_at"])
    _org_policy("scan_runs")

    op.create_table(
        "scan_targets",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("org_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("run_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "context_scope", postgresql.JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")
        ),
        sa.Column(
            "frozen_identity",
            postgresql.JSONB,
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("state", sa.String(24), nullable=False, server_default="QUEUED"),
        sa.Column("error_code", sa.String(64)),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("finished_at", sa.DateTime(timezone=True)),
        sa.UniqueConstraint("org_id", "id", name="uq_scan_targets_org_id"),
        sa.UniqueConstraint("org_id", "run_id", "asset_id", name="uq_scan_targets_run_asset"),
        sa.ForeignKeyConstraint(
            ["org_id", "run_id"], ["scan_runs.org_id", "scan_runs.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["org_id", "asset_id"], ["assets.org_id", "assets.id"], ondelete="RESTRICT"
        ),
        sa.CheckConstraint(
            "state IN ('QUEUED', 'PREFLIGHT', 'COLLECTING', 'NORMALIZING', "
            "'EVALUATING', 'RETRY_WAIT', 'COMPLETED', 'PARTIAL', 'FAILED', 'CANCELLED')",
            name="ck_scan_targets_state",
        ),
    )
    op.create_index("ix_scan_targets_org_state", "scan_targets", ["org_id", "state"])
    _org_policy("scan_targets")

    op.create_table(
        "jobs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("org_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("target_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("state", sa.String(24), nullable=False, server_default="QUEUED"),
        sa.Column("attempt", sa.Integer, nullable=False, server_default="0"),
        sa.Column("max_attempts", sa.Integer, nullable=False, server_default="3"),
        sa.Column(
            "available_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column("lease_owner", postgresql.UUID(as_uuid=True)),
        sa.Column("lease_token", postgresql.UUID(as_uuid=True)),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True)),
        sa.Column(
            "payload_ref", postgresql.JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")
        ),
        sa.ForeignKeyConstraint(
            ["org_id", "target_id"], ["scan_targets.org_id", "scan_targets.id"], ondelete="CASCADE"
        ),
        sa.CheckConstraint(
            "state IN ('QUEUED', 'RUNNING', 'RETRY_WAIT', 'COMPLETED', 'DEAD_LETTER', 'CANCELLED')",
            name="ck_jobs_state",
        ),
        sa.CheckConstraint(
            "attempt >= 0 AND max_attempts BETWEEN 1 AND 10", name="ck_jobs_attempts"
        ),
    )
    op.create_index(
        "ix_jobs_ready",
        "jobs",
        ["state", "available_at", "id"],
        postgresql_where=sa.text("state IN ('QUEUED', 'RETRY_WAIT')"),
    )
    op.create_index(
        "ix_jobs_expired_lease",
        "jobs",
        ["lease_expires_at"],
        postgresql_where=sa.text("lease_expires_at IS NOT NULL"),
    )
    _org_policy("jobs")

    op.create_table(
        "audit_events",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "org_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organizations.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("sequence", sa.BigInteger, nullable=False),
        sa.Column("actor_id", postgresql.UUID(as_uuid=True)),
        sa.Column("action", sa.String(100), nullable=False),
        sa.Column("object_type", sa.String(100), nullable=False),
        sa.Column("object_id", postgresql.UUID(as_uuid=True)),
        sa.Column(
            "redacted_details",
            postgresql.JSONB,
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("previous_hash", sa.String(64), nullable=False),
        sa.Column("event_hash", sa.String(64), nullable=False),
        sa.Column(
            "occurred_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.UniqueConstraint("org_id", "sequence", name="uq_audit_events_sequence"),
        sa.CheckConstraint(
            "previous_hash ~ '^[0-9a-f]{64}$' AND event_hash ~ '^[0-9a-f]{64}$'",
            name="ck_audit_events_hash",
        ),
    )
    op.create_index("ix_audit_events_org_time", "audit_events", ["org_id", "occurred_at"])
    _org_policy("audit_events")

    op.create_table(
        "idempotency_keys",
        sa.Column("org_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("principal_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("route", sa.String(200), primary_key=True),
        sa.Column("key", sa.String(200), primary_key=True),
        sa.Column("request_digest", sa.String(64), nullable=False),
        sa.Column("response_ref", postgresql.JSONB),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.CheckConstraint(
            "request_digest ~ '^[0-9a-f]{64}$'", name="ck_idempotency_request_digest"
        ),
    )
    op.create_index("ix_idempotency_expiry", "idempotency_keys", ["expires_at"])
    _org_policy("idempotency_keys")

    op.execute("""
    CREATE FUNCTION reject_published_policy_mutation() RETURNS trigger
    LANGUAGE plpgsql AS $$
    BEGIN
      IF OLD.state = 'published' AND (
        NEW.org_id IS DISTINCT FROM OLD.org_id OR
        NEW.name IS DISTINCT FROM OLD.name OR
        NEW.revision IS DISTINCT FROM OLD.revision OR
        NEW.spec IS DISTINCT FROM OLD.spec OR
        NEW.digest IS DISTINCT FROM OLD.digest OR
        NEW.author_id IS DISTINCT FROM OLD.author_id OR
        NEW.approver_id IS DISTINCT FROM OLD.approver_id OR
        NEW.published_at IS DISTINCT FROM OLD.published_at
      ) THEN
        RAISE EXCEPTION 'published policy content is immutable';
      END IF;
      RETURN NEW;
    END;
    $$
    """)
    op.execute(
        "CREATE TRIGGER trg_published_policy_immutable BEFORE UPDATE ON policies "
        "FOR EACH ROW EXECUTE FUNCTION reject_published_policy_mutation()"
    )
    op.execute("""
    CREATE FUNCTION reject_audit_event_mutation() RETURNS trigger
    LANGUAGE plpgsql AS $$
    BEGIN
      RAISE EXCEPTION 'audit events are append-only';
    END;
    $$
    """)
    op.execute(
        "CREATE TRIGGER trg_audit_event_immutable BEFORE UPDATE OR DELETE ON audit_events "
        "FOR EACH ROW EXECUTE FUNCTION reject_audit_event_mutation()"
    )
    # The API role is provisioned by deployment, not by the migration. Keep a
    # fresh database usable without granting cross-tenant or schema-owner access.
    op.execute("""
    DO $$
    BEGIN
      IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'bg_api') THEN
        EXECUTE 'GRANT USAGE ON SCHEMA public TO bg_api';
        EXECUTE 'GRANT SELECT ON rule_packs TO bg_api';
        EXECUTE 'GRANT SELECT, INSERT, UPDATE ON sites, assets, policies, policy_pack_links, '
          || 'scan_runs, scan_targets, jobs, idempotency_keys TO bg_api';
        EXECUTE 'GRANT SELECT, INSERT ON audit_events TO bg_api';
      END IF;
    END
    $$
    """)


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS trg_audit_event_immutable ON audit_events")
    op.execute("DROP FUNCTION IF EXISTS reject_audit_event_mutation()")
    op.execute("DROP TRIGGER IF EXISTS trg_published_policy_immutable ON policies")
    op.execute("DROP FUNCTION IF EXISTS reject_published_policy_mutation()")
    for table in (
        "idempotency_keys",
        "audit_events",
        "jobs",
        "scan_targets",
        "scan_runs",
        "policy_pack_links",
        "policies",
        "rule_packs",
        "assets",
        "sites",
        "organizations",
    ):
        op.drop_table(table)
