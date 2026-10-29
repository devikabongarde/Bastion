"""Pipeline core: snapshots, artifacts, evidence, results, findings, exceptions,
manual reviews, reports, schedules, credentials, trust and intent records.

Revision ID: 0004_pipeline
Revises: 0003_local_identity
"""

from typing import Any

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql as pg

revision = "0004_pipeline"
down_revision = "0003_local_identity"
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



def create_table(name: str, *items: Any, **kwargs: Any) -> None:
    """Create a table; tenant tables get the (org_id, id) key composite foreign keys reference."""
    columns = {item.name for item in items if isinstance(item, sa.Column)}
    declared = {getattr(item, "name", None) for item in items}
    unique_name = f"uq_{name}_org_id"
    if {"id", "org_id"} <= columns and unique_name not in declared:
        items = (*items, sa.UniqueConstraint("org_id", "id", name=unique_name))
    op.create_table(name, *items, **kwargs)


def scoped(table: str) -> None:
    predicate = "org_id = nullif(current_setting('app.org_id', true), '')::uuid"
    op.execute(f'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY')
    op.execute(f'ALTER TABLE "{table}" FORCE ROW LEVEL SECURITY')
    op.execute(
        f'CREATE POLICY "{table}_org_isolation" ON "{table}" '
        f"USING ({predicate}) WITH CHECK ({predicate})"
    )


def upgrade() -> None:
    # Pipeline tables plus a job diagnostic column the older migrations lack.
    op.add_column("jobs", sa.Column("error_code", sa.String(64), nullable=True))
    create_table(
        "artifacts",
        sa.Column("id", pg.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "org_id", pg.UUID(as_uuid=True), sa.ForeignKey("organizations.id"), nullable=False
        ),
        sa.Column("storage_key", sa.String(256), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("media_type", sa.String(100), nullable=False),
        sa.Column("size_bytes", sa.BigInteger, nullable=False),
        sa.Column("classification", sa.String(24), nullable=False, server_default="redacted"),
        sa.Column("encrypted", sa.Boolean, nullable=False, server_default=sa.text("true")),
        sa.Column("key_version", sa.String(64), nullable=False),
        sa.Column("retention_until", sa.DateTime(timezone=True)),
        sa.Column("legal_hold", sa.Boolean, nullable=False, server_default=sa.text("false")),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.UniqueConstraint("org_id", "storage_key", name="uq_artifacts_store_key"),
        sa.CheckConstraint("size_bytes > 0", name="ck_artifacts_size"),
        sa.CheckConstraint("sha256 ~ '^[0-9a-f]{64}$'", name="ck_artifacts_sha256"),
        sa.CheckConstraint(
            "classification IN ('redacted', 'normalized', 'report', 'raw_restricted')",
            name="ck_artifacts_classification",
        ),
    )
    op.create_index("ix_artifacts_org_sha", "artifacts", ["org_id", "sha256"])
    scoped("artifacts")

    create_table(
        "snapshots",
        sa.Column("id", pg.UUID(as_uuid=True), primary_key=True),
        sa.Column("org_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("target_id", pg.UUID(as_uuid=True)),
        sa.Column("asset_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("source", sa.String(16), nullable=False),
        sa.Column("identity", pg.JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("configuration_plane", sa.String(64), nullable=False, server_default="effective"),
        sa.Column("observed_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("observed_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("digest", sa.String(64), nullable=False),
        sa.Column("completeness", pg.JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("provenance", pg.JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(
            ["org_id", "target_id"], ["scan_targets.org_id", "scan_targets.id"]
        ),
        sa.ForeignKeyConstraint(
            ["org_id", "asset_id"], ["assets.org_id", "assets.id"], ondelete="RESTRICT"
        ),
        sa.CheckConstraint(
            "source IN ('live', 'import', 'replay', 'fixture')", name="ck_snapshots_source"
        ),
        sa.CheckConstraint("digest ~ '^[0-9a-f]{64}$'", name="ck_snapshots_digest"),
        sa.CheckConstraint("observed_end >= observed_start", name="ck_snapshots_observation_order"),
    )
    op.create_index(
        "ix_snapshots_asset_received", "snapshots", ["org_id", "asset_id", "received_at"]
    )
    op.create_index("ix_snapshots_digest", "snapshots", ["org_id", "digest"])
    scoped("snapshots")

    create_table(
        "evidence_refs",
        sa.Column("id", pg.UUID(as_uuid=True), primary_key=True),
        sa.Column("org_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("snapshot_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("artifact_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("reader_id", sa.String(200), nullable=False),
        sa.Column("pointer", pg.JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("redaction_version", sa.String(64), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(
            ["org_id", "snapshot_id"], ["snapshots.org_id", "snapshots.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["org_id", "artifact_id"], ["artifacts.org_id", "artifacts.id"], ondelete="RESTRICT"
        ),
    )
    op.create_index("ix_evidence_refs_snapshot", "evidence_refs", ["org_id", "snapshot_id"])
    scoped("evidence_refs")

    create_table(
        "result_sets",
        sa.Column("id", pg.UUID(as_uuid=True), primary_key=True),
        sa.Column("org_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("run_id", pg.UUID(as_uuid=True)),
        sa.Column("target_id", pg.UUID(as_uuid=True)),
        sa.Column("snapshot_id", pg.UUID(as_uuid=True)),
        sa.Column("asset_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("policy_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("engine_digest", sa.String(64), nullable=False),
        sa.Column("view", sa.String(64), nullable=False, server_default="primary"),
        sa.Column("semantic_digest", sa.String(64), nullable=False),
        sa.Column("summary", pg.JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("replay_of", pg.UUID(as_uuid=True)),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(["org_id", "run_id"], ["scan_runs.org_id", "scan_runs.id"]),
        sa.ForeignKeyConstraint(
            ["org_id", "target_id"], ["scan_targets.org_id", "scan_targets.id"]
        ),
        sa.ForeignKeyConstraint(["org_id", "snapshot_id"], ["snapshots.org_id", "snapshots.id"]),
        sa.ForeignKeyConstraint(["org_id", "asset_id"], ["assets.org_id", "assets.id"]),
        sa.ForeignKeyConstraint(["org_id", "policy_id"], ["policies.org_id", "policies.id"]),
        sa.ForeignKeyConstraint(["org_id", "replay_of"], ["result_sets.org_id", "result_sets.id"]),
        sa.CheckConstraint("engine_digest ~ '^[0-9a-f]{64}$'", name="ck_result_sets_engine_digest"),
        sa.CheckConstraint(
            "semantic_digest ~ '^[0-9a-f]{64}$'", name="ck_result_sets_semantic_digest"
        ),
        sa.CheckConstraint(
            "view IN ('primary', 'original_profile', 'tailored')", name="ck_result_sets_view"
        ),
        sa.UniqueConstraint(
            "org_id", "run_id", "asset_id", "policy_id", "view", name="uq_result_sets_finalized"
        ),
    )
    op.create_index(
        "ix_result_sets_asset_completed", "result_sets", ["org_id", "asset_id", "completed_at"]
    )
    scoped("result_sets")

    create_table(
        "control_results",
        sa.Column("id", pg.UUID(as_uuid=True), primary_key=True),
        sa.Column("org_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("result_set_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("control_key", sa.String(200), nullable=False),
        sa.Column("control_revision", sa.Integer, nullable=False),
        sa.Column("context_key", sa.String(200), nullable=False, server_default="global"),
        sa.Column("resource_key", sa.String(200), nullable=False, server_default="__control__"),
        sa.Column("status", sa.String(24), nullable=False),
        sa.Column("reason_code", sa.String(100), nullable=False),
        sa.Column("expected", pg.JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("actual", pg.JSONB),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("assessment_quality", sa.String(24), nullable=False),
        sa.Column("trace", pg.JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("counts_toward_score", sa.Boolean, nullable=False),
        sa.Column("parent_result_id", pg.UUID(as_uuid=True)),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(
            ["org_id", "result_set_id"],
            ["result_sets.org_id", "result_sets.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["org_id", "parent_result_id"], ["control_results.org_id", "control_results.id"]
        ),
        sa.CheckConstraint(
            "status IN ('PASS', 'FAIL', 'NOT_APPLICABLE', 'UNKNOWN', 'ERROR', 'MANUAL_REQUIRED')",
            name="ck_control_results_status",
        ),
        sa.CheckConstraint(
            "severity IN ('critical', 'high', 'medium', 'low')", name="ck_control_results_severity"
        ),
        sa.CheckConstraint(
            "assessment_quality IN ('proven', 'manual_verified', 'incomplete', 'advisory')",
            name="ck_control_results_quality",
        ),
        sa.CheckConstraint(
            "(counts_toward_score = true AND resource_key = '__control__' "
            "AND parent_result_id IS NULL) OR "
            "(counts_toward_score = false AND resource_key <> '__control__' "
            "AND parent_result_id IS NOT NULL)",
            name="ck_control_results_granularity",
        ),
        sa.UniqueConstraint(
            "result_set_id",
            "control_key",
            "context_key",
            "resource_key",
            name="uq_control_results_identity",
        ),
    )
    op.create_index("ix_control_results_result_set", "control_results", ["org_id", "result_set_id"])
    op.create_index("ix_control_results_status", "control_results", ["org_id", "status"])
    scoped("control_results")

    create_table(
        "result_evidence",
        sa.Column("org_id", pg.UUID(as_uuid=True), primary_key=True),
        sa.Column("result_id", pg.UUID(as_uuid=True), primary_key=True),
        sa.Column("evidence_ref_id", pg.UUID(as_uuid=True), primary_key=True),
        sa.ForeignKeyConstraint(
            ["org_id", "result_id"],
            ["control_results.org_id", "control_results.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["org_id", "evidence_ref_id"], ["evidence_refs.org_id", "evidence_refs.id"]
        ),
    )
    scoped("result_evidence")

    create_table(
        "findings",
        sa.Column("id", pg.UUID(as_uuid=True), primary_key=True),
        sa.Column("org_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("asset_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("control_key", sa.String(200), nullable=False),
        sa.Column("control_revision", sa.Integer, nullable=False),
        sa.Column("context_key", sa.String(200), nullable=False, server_default="global"),
        sa.Column("resource_key", sa.String(200), nullable=False),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("state", sa.String(24), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_result_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("owner_id", pg.UUID(as_uuid=True)),
        sa.Column("due_at", sa.DateTime(timezone=True)),
        *timestamps(),
        sa.ForeignKeyConstraint(
            ["org_id", "asset_id"], ["assets.org_id", "assets.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["org_id", "owner_id"], ["users.org_id", "users.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["org_id", "last_result_id"], ["control_results.org_id", "control_results.id"]
        ),
        sa.CheckConstraint(
            "state IN ('OPEN', 'RESOLVED', 'RISK_ACCEPTED')", name="ck_findings_state"
        ),
        sa.CheckConstraint(
            "severity IN ('critical', 'high', 'medium', 'low')", name="ck_findings_severity"
        ),
        sa.UniqueConstraint(
            "org_id",
            "asset_id",
            "control_key",
            "context_key",
            "resource_key",
            name="uq_findings_stable_key",
        ),
    )
    op.create_index("ix_findings_state", "findings", ["org_id", "state", "severity"])
    op.create_index("ix_findings_owner", "findings", ["org_id", "owner_id"])
    scoped("findings")

    create_table(
        "finding_events",
        sa.Column("id", pg.UUID(as_uuid=True), primary_key=True),
        sa.Column("org_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("finding_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("kind", sa.String(64), nullable=False),
        sa.Column("actor_id", pg.UUID(as_uuid=True)),
        sa.Column("result_id", pg.UUID(as_uuid=True)),
        sa.Column("payload", pg.JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column(
            "occurred_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(
            ["org_id", "finding_id"], ["findings.org_id", "findings.id"], ondelete="CASCADE"
        ),
        sa.CheckConstraint(
            "kind IN ('OPENED', 'STILL_FAILING', 'FIXED_VERIFIED', 'CLOSED_NO_LONGER_APPLICABLE', "
            "'ASSIGNED', 'DUE_SET', 'COMMENT', 'EXCEPTION_LINKED', 'MANUAL_REVIEW')",
            name="ck_finding_events_kind",
        ),
    )
    op.create_index(
        "ix_finding_events_finding", "finding_events", ["org_id", "finding_id", "occurred_at"]
    )
    scoped("finding_events")

    create_table(
        "exceptions",
        sa.Column("id", pg.UUID(as_uuid=True), primary_key=True),
        sa.Column("org_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("asset_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("control_key", sa.String(200), nullable=False),
        sa.Column("reason", sa.String(2000), nullable=False),
        sa.Column("compensating_controls", sa.String(2000), nullable=False),
        sa.Column("requested_by", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("approved_by", pg.UUID(as_uuid=True)),
        sa.Column("approved_at", sa.DateTime(timezone=True)),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("state", sa.String(24), nullable=False),
        *timestamps(),
        sa.ForeignKeyConstraint(
            ["org_id", "asset_id"], ["assets.org_id", "assets.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["org_id", "requested_by"], ["users.org_id", "users.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["org_id", "approved_by"], ["users.org_id", "users.id"], ondelete="RESTRICT"
        ),
        sa.CheckConstraint(
            "state IN ('REQUESTED', 'APPROVED', 'REVOKED', 'REJECTED')", name="ck_exceptions_state"
        ),
        sa.CheckConstraint("expires_at > created_at", name="ck_exceptions_expiry_future"),
        sa.CheckConstraint(
            "state <> 'APPROVED' OR approved_by IS NOT NULL",
            name="ck_exceptions_approved_has_approver",
        ),
    )
    op.create_index("ix_exceptions_expiry", "exceptions", ["org_id", "state", "expires_at"])
    op.create_index(
        "ix_exceptions_asset_control", "exceptions", ["org_id", "asset_id", "control_key"]
    )
    scoped("exceptions")

    create_table(
        "manual_reviews",
        sa.Column("id", pg.UUID(as_uuid=True), primary_key=True),
        sa.Column("org_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("result_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("decision", sa.String(40), nullable=False),
        sa.Column("rationale", sa.String(2000), nullable=False),
        sa.Column("evidence_refs", pg.JSONB, nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("reviewer_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("supersedes_id", pg.UUID(as_uuid=True)),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(
            ["org_id", "result_id"], ["control_results.org_id", "control_results.id"]
        ),
        sa.ForeignKeyConstraint(
            ["org_id", "reviewer_id"], ["users.org_id", "users.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["org_id", "supersedes_id"], ["manual_reviews.org_id", "manual_reviews.id"]
        ),
        sa.CheckConstraint(
            "decision IN ('CONFIRMED_PASS', 'CONFIRMED_FAIL', 'REJECTED_ASSESSMENT')",
            name="ck_manual_reviews_decision",
        ),
    )
    op.create_index("ix_manual_reviews_result", "manual_reviews", ["org_id", "result_id"])
    scoped("manual_reviews")

    create_table(
        "reports",
        sa.Column("id", pg.UUID(as_uuid=True), primary_key=True),
        sa.Column("org_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("requested_by", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("run_id", pg.UUID(as_uuid=True)),
        sa.Column("format", sa.String(16), nullable=False),
        sa.Column("scope_manifest", pg.JSONB, nullable=False),
        sa.Column("cutoff_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("state", sa.String(24), nullable=False, server_default="QUEUED"),
        sa.Column("artifact_id", pg.UUID(as_uuid=True)),
        sa.Column("manifest_digest", sa.String(64)),
        sa.Column("error_code", sa.String(64)),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(
            ["org_id", "requested_by"], ["users.org_id", "users.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(["org_id", "run_id"], ["scan_runs.org_id", "scan_runs.id"]),
        sa.ForeignKeyConstraint(["org_id", "artifact_id"], ["artifacts.org_id", "artifacts.id"]),
        sa.CheckConstraint("format IN ('json', 'html', 'csv', 'pdf')", name="ck_reports_format"),
        sa.CheckConstraint(
            "state IN ('QUEUED', 'RENDERING', 'COMPLETED', 'FAILED')", name="ck_reports_state"
        ),
        sa.CheckConstraint(
            "state <> 'COMPLETED' OR artifact_id IS NOT NULL", name="ck_reports_completed_artifact"
        ),
    )
    op.create_index("ix_reports_org_created", "reports", ["org_id", "created_at"])
    scoped("reports")

    create_table(
        "schedules",
        sa.Column("id", pg.UUID(as_uuid=True), primary_key=True),
        sa.Column("org_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("site_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("policy_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("cron", sa.String(100), nullable=False),
        sa.Column("timezone", sa.String(100), nullable=False),
        sa.Column("overlap_policy", sa.String(16), nullable=False, server_default="skip"),
        sa.Column("enabled", sa.Boolean, nullable=False, server_default=sa.text("true")),
        sa.Column("created_by", pg.UUID(as_uuid=True), nullable=False),
        *timestamps(),
        sa.ForeignKeyConstraint(["org_id", "site_id"], ["sites.org_id", "sites.id"]),
        sa.ForeignKeyConstraint(["org_id", "policy_id"], ["policies.org_id", "policies.id"]),
        sa.ForeignKeyConstraint(["org_id", "created_by"], ["users.org_id", "users.id"]),
        sa.UniqueConstraint("org_id", "name", name="uq_schedules_name"),
        sa.CheckConstraint("overlap_policy IN ('skip', 'reschedule')", name="ck_schedules_overlap"),
    )
    op.create_index("ix_schedules_enabled", "schedules", ["org_id", "enabled"])
    scoped("schedules")

    create_table(
        "schedule_occurrences",
        sa.Column("org_id", pg.UUID(as_uuid=True), primary_key=True),
        sa.Column("schedule_id", pg.UUID(as_uuid=True), primary_key=True),
        sa.Column("occurrence_at", sa.DateTime(timezone=True), primary_key=True),
        sa.Column("status", sa.String(16), nullable=False, server_default="ENQUEUED"),
        sa.Column("run_id", pg.UUID(as_uuid=True)),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(
            ["org_id", "schedule_id"], ["schedules.org_id", "schedules.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(["org_id", "run_id"], ["scan_runs.org_id", "scan_runs.id"]),
        sa.CheckConstraint(
            "status IN ('ENQUEUED', 'COMPLETED', 'SKIPPED')", name="ck_occurrence_status"
        ),
    )
    scoped("schedule_occurrences")

    create_table(
        "credentials",
        sa.Column("id", pg.UUID(as_uuid=True), primary_key=True),
        sa.Column("org_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("kind", sa.String(24), nullable=False),
        sa.Column("encrypted_secret", sa.LargeBinary),
        sa.Column("key_version", sa.String(64), nullable=False),
        sa.Column("metadata", pg.JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("created_by", pg.UUID(as_uuid=True), nullable=False),
        *timestamps(),
        sa.ForeignKeyConstraint(
            ["org_id", "created_by"], ["users.org_id", "users.id"], ondelete="RESTRICT"
        ),
        sa.UniqueConstraint("org_id", "name", name="uq_credentials_name"),
        sa.CheckConstraint(
            "kind IN ('ssh_key', 'ssh_password', 'api_token')", name="ck_credentials_kind"
        ),
        sa.CheckConstraint(
            "encrypted_secret IS NOT NULL OR metadata ? 'external_ref'",
            name="ck_credentials_material_or_ref",
        ),
    )
    op.create_index("ix_credentials_org_kind", "credentials", ["org_id", "kind"])
    scoped("credentials")

    create_table(
        "asset_credentials",
        sa.Column("org_id", pg.UUID(as_uuid=True), primary_key=True),
        sa.Column("asset_id", pg.UUID(as_uuid=True), primary_key=True),
        sa.Column("credential_id", pg.UUID(as_uuid=True), primary_key=True),
        sa.Column("purpose", sa.String(40), primary_key=True),
        sa.ForeignKeyConstraint(
            ["org_id", "asset_id"], ["assets.org_id", "assets.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["org_id", "credential_id"],
            ["credentials.org_id", "credentials.id"],
            ondelete="CASCADE",
        ),
        sa.CheckConstraint(
            "purpose IN ('audit_collect', 'preflight')", name="ck_asset_credentials_purpose"
        ),
    )
    scoped("asset_credentials")

    create_table(
        "asset_trust",
        sa.Column("id", pg.UUID(as_uuid=True), primary_key=True),
        sa.Column("org_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("asset_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("trust_type", sa.String(40), nullable=False),
        sa.Column("fingerprint", sa.String(256), nullable=False),
        sa.Column("verified_by", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        *timestamps(),
        sa.ForeignKeyConstraint(
            ["org_id", "asset_id"], ["assets.org_id", "assets.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["org_id", "verified_by"], ["users.org_id", "users.id"], ondelete="RESTRICT"
        ),
        sa.CheckConstraint(
            "trust_type IN ('ssh_host_key', 'tls_certificate')", name="ck_asset_trust_type"
        ),
    )
    op.create_index(
        "uq_asset_trust_active_fingerprint",
        "asset_trust",
        ["org_id", "asset_id", "trust_type", "fingerprint"],
        unique=True,
        postgresql_where=sa.text("revoked_at IS NULL"),
    )
    scoped("asset_trust")

    create_table(
        "intent_records",
        sa.Column("id", pg.UUID(as_uuid=True), primary_key=True),
        sa.Column("org_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("asset_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("resource_key", sa.String(200), nullable=False),
        sa.Column("kind", sa.String(40), nullable=False),
        sa.Column("value", pg.JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("approved_by", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        *timestamps(),
        sa.ForeignKeyConstraint(
            ["org_id", "asset_id"], ["assets.org_id", "assets.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["org_id", "approved_by"], ["users.org_id", "users.id"], ondelete="RESTRICT"
        ),
        sa.CheckConstraint("kind IN ('port_purpose')", name="ck_intent_records_kind"),
    )
    op.create_index(
        "ix_intent_records_asset", "intent_records", ["org_id", "asset_id", "resource_key"]
    )
    scoped("intent_records")

    # Immutable rows: snapshots/artifacts/evidence/results/results-with-children
    # and findings/exception history never change after insert.
    immutables = {
        "snapshot_rows": [
            "snapshots",
            "artifacts",
            "evidence_refs",
            "result_sets",
            "control_results",
            "finding_events",
            "manual_reviews",
            "schedule_occurrences",
        ],
    }
    op.execute("""
    CREATE FUNCTION reject_row_mutation() RETURNS trigger
    LANGUAGE plpgsql AS $$
    BEGIN
      RAISE EXCEPTION 'rows in this table are immutable; create a new revision instead';
    END;
    $$
    """)
    for table in immutables["snapshot_rows"]:
        op.execute(
            f"CREATE TRIGGER trg_{table}_immutable BEFORE UPDATE OR DELETE ON {table} "
            "FOR EACH ROW EXECUTE FUNCTION reject_row_mutation()"
        )

    op.execute("""
    DO $$
    BEGIN
      IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'bg_api') THEN
        EXECUTE 'GRANT SELECT, INSERT, UPDATE ON snapshots, artifacts, evidence_refs,
          result_sets, control_results, reports, schedules, assets, scan_runs,
          scan_targets,
          jobs,
          idempotency_keys TO bg_api';
        EXECUTE 'GRANT SELECT, INSERT, UPDATE ON findings TO bg_api';
        EXECUTE 'GRANT SELECT, INSERT ON finding_events, manual_reviews,
          schedule_occurrences, intent_records, asset_trust, exceptions TO bg_api';
        EXECUTE 'GRANT SELECT, INSERT, DELETE ON asset_credentials TO bg_api';
        EXECUTE 'GRANT SELECT ON credentials TO bg_api';
      END IF;
    END
    $$""")


def downgrade() -> None:
    tables = (
        "intent_records",
        "asset_trust",
        "asset_credentials",
        "credentials",
        "schedule_occurrences",
        "schedules",
        "reports",
        "manual_reviews",
        "exceptions",
        "finding_events",
        "findings",
        "result_evidence",
        "control_results",
        "result_sets",
        "evidence_refs",
        "snapshots",
        "artifacts",
    )
    for table in tables:
        op.execute(f"DROP TRIGGER IF EXISTS trg_{table}_immutable ON {table}")
    op.execute("DROP FUNCTION IF EXISTS reject_row_mutation()")
    for table in tables:
        op.drop_table(table)
    op.drop_column("jobs", "error_code")
