from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    LargeBinary,
    String,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class Timestamped:
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )
    row_version: Mapped[int] = mapped_column(BigInteger, server_default="1", nullable=False)


class Organization(Base, Timestamped):
    __tablename__ = "organizations"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    slug: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    settings: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    status: Mapped[str] = mapped_column(String(24), default="active", nullable=False)

    __table_args__ = (
        CheckConstraint(
            "status IN ('active', 'suspended', 'archived')", name="ck_organizations_status"
        ),
    )


class Site(Base, Timestamped):
    __tablename__ = "sites"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    org_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="RESTRICT"),
        nullable=False,
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    timezone: Mapped[str] = mapped_column(String(100), nullable=False)
    scope: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)

    __table_args__ = (
        UniqueConstraint("org_id", "id", name="uq_sites_org_id"),
        UniqueConstraint("org_id", "name", name="uq_sites_org_name"),
        Index("ix_sites_org", "org_id"),
    )


class Asset(Base, Timestamped):
    __tablename__ = "assets"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    org_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    site_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    category: Mapped[str] = mapped_column(String(24), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    address: Mapped[str] = mapped_column(String(253), nullable=False)
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    adapter_id: Mapped[str] = mapped_column(String(100), nullable=False)
    declared_role: Mapped[str] = mapped_column(String(100), nullable=False)
    identity: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    criticality: Mapped[str] = mapped_column(String(16), default="normal", nullable=False)
    owner_id: Mapped[UUID | None] = mapped_column(PGUUID(as_uuid=True))
    tags: Mapped[dict[str, str]] = mapped_column(JSONB, default=dict, nullable=False)
    archived_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    site: Mapped[Site] = relationship()

    __table_args__ = (
        UniqueConstraint("org_id", "id", name="uq_assets_org_id"),
        ForeignKeyConstraint(
            ["org_id", "site_id"], ["sites.org_id", "sites.id"], ondelete="RESTRICT"
        ),
        CheckConstraint(
            "category IN ('windows', 'linux', 'firewall', 'router', 'switch')",
            name="ck_assets_category",
        ),
        CheckConstraint(
            "criticality IN ('critical', 'high', 'normal', 'low')", name="ck_assets_criticality"
        ),
        CheckConstraint("port BETWEEN 1 AND 65535", name="ck_assets_port"),
        Index("ix_assets_org_site_category", "org_id", "site_id", "category"),
        Index("ix_assets_org_updated", "org_id", "updated_at"),
        Index(
            "uq_assets_active_endpoint",
            "org_id",
            "site_id",
            "address",
            "port",
            "adapter_id",
            unique=True,
            postgresql_where=text("archived_at IS NULL"),
        ),
    )


class RulePack(Base, Timestamped):
    __tablename__ = "rule_packs"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    org_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    pack_key: Mapped[str] = mapped_column(String(200), nullable=False)
    version: Mapped[str] = mapped_column(String(64), nullable=False)
    digest: Mapped[str] = mapped_column(String(64), nullable=False)
    manifest: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    rights_metadata: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    state: Mapped[str] = mapped_column(String(24), nullable=False)

    __table_args__ = (
        UniqueConstraint("org_id", "id", name="uq_rule_packs_org_id"),
        ForeignKeyConstraint(["org_id"], ["organizations.id"], ondelete="RESTRICT"),
        UniqueConstraint("org_id", "pack_key", "version", name="uq_rule_packs_version"),
        CheckConstraint("state IN ('draft', 'approved', 'revoked')", name="ck_rule_packs_state"),
        CheckConstraint("digest ~ '^[0-9a-f]{64}$'", name="ck_rule_packs_digest"),
        Index("ix_rule_packs_org_state", "org_id", "state"),
    )


class Policy(Base, Timestamped):
    __tablename__ = "policies"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    org_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    revision: Mapped[int] = mapped_column(Integer, nullable=False)
    spec: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    digest: Mapped[str] = mapped_column(String(64), nullable=False)
    state: Mapped[str] = mapped_column(String(24), nullable=False)
    author_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    approver_id: Mapped[UUID | None] = mapped_column(PGUUID(as_uuid=True))
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        UniqueConstraint("org_id", "id", name="uq_policies_org_id"),
        ForeignKeyConstraint(["org_id"], ["organizations.id"], ondelete="RESTRICT"),
        UniqueConstraint("org_id", "name", "revision", name="uq_policies_revision"),
        CheckConstraint("revision > 0", name="ck_policies_revision"),
        CheckConstraint("state IN ('draft', 'published', 'revoked')", name="ck_policies_state"),
        CheckConstraint("digest ~ '^[0-9a-f]{64}$'", name="ck_policies_digest"),
        CheckConstraint(
            "state <> 'published' OR (approver_id IS NOT NULL "
            "AND approver_id <> author_id AND published_at IS NOT NULL)",
            name="ck_policies_two_person_publish",
        ),
        Index("ix_policies_org_state", "org_id", "state"),
    )


class PolicyPack(Base):
    __tablename__ = "policy_pack_links"

    org_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    policy_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    rule_pack_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    pack_digest: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        ForeignKeyConstraint(
            ["org_id", "policy_id"], ["policies.org_id", "policies.id"], ondelete="RESTRICT"
        ),
        ForeignKeyConstraint(
            ["org_id", "rule_pack_id"], ["rule_packs.org_id", "rule_packs.id"], ondelete="RESTRICT"
        ),
    )


class ScanRun(Base):
    __tablename__ = "scan_runs"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    org_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    policy_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    requester_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    reason: Mapped[str] = mapped_column(String(500), nullable=False)
    scope_manifest: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    status: Mapped[str] = mapped_column(String(24), default="QUEUED", nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    targets: Mapped[list[ScanTarget]] = relationship(
        back_populates="run", cascade="all, delete-orphan"
    )

    __table_args__ = (
        UniqueConstraint("org_id", "id", name="uq_scan_runs_org_id"),
        ForeignKeyConstraint(
            ["org_id", "policy_id"], ["policies.org_id", "policies.id"], ondelete="RESTRICT"
        ),
        CheckConstraint(
            "status IN ('QUEUED', 'PREFLIGHT', 'COLLECTING', 'NORMALIZING', "
            "'EVALUATING', 'RETRY_WAIT', 'COMPLETED', 'PARTIAL', 'FAILED', 'CANCELLED')",
            name="ck_scan_runs_status",
        ),
        Index("ix_scan_runs_org_created", "org_id", "created_at"),
    )


class ScanTarget(Base):
    __tablename__ = "scan_targets"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    org_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    run_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    asset_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    context_scope: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    frozen_identity: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    state: Mapped[str] = mapped_column(String(24), default="QUEUED", nullable=False)
    error_code: Mapped[str | None] = mapped_column(String(64))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    run: Mapped[ScanRun] = relationship(back_populates="targets")

    __table_args__ = (
        UniqueConstraint("org_id", "id", name="uq_scan_targets_org_id"),
        UniqueConstraint("org_id", "run_id", "asset_id", name="uq_scan_targets_run_asset"),
        ForeignKeyConstraint(
            ["org_id", "run_id"], ["scan_runs.org_id", "scan_runs.id"], ondelete="CASCADE"
        ),
        ForeignKeyConstraint(
            ["org_id", "asset_id"], ["assets.org_id", "assets.id"], ondelete="RESTRICT"
        ),
        CheckConstraint(
            "state IN ('QUEUED', 'PREFLIGHT', 'COLLECTING', 'NORMALIZING', "
            "'EVALUATING', 'RETRY_WAIT', 'COMPLETED', 'PARTIAL', 'FAILED', 'CANCELLED')",
            name="ck_scan_targets_state",
        ),
        Index("ix_scan_targets_org_state", "org_id", "state"),
    )


class Job(Base):
    __tablename__ = "jobs"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    org_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    target_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    state: Mapped[str] = mapped_column(String(24), default="QUEUED", nullable=False)
    attempt: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    max_attempts: Mapped[int] = mapped_column(Integer, default=3, nullable=False)
    available_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    lease_owner: Mapped[UUID | None] = mapped_column(PGUUID(as_uuid=True))
    lease_token: Mapped[UUID | None] = mapped_column(PGUUID(as_uuid=True))
    lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    cancel_requested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error_code: Mapped[str | None] = mapped_column(String(64))
    payload_ref: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)

    __table_args__ = (
        ForeignKeyConstraint(
            ["org_id", "target_id"], ["scan_targets.org_id", "scan_targets.id"], ondelete="CASCADE"
        ),
        CheckConstraint(
            "state IN ('QUEUED', 'RUNNING', 'RETRY_WAIT', 'COMPLETED', 'DEAD_LETTER', 'CANCELLED')",
            name="ck_jobs_state",
        ),
        CheckConstraint("attempt >= 0 AND max_attempts BETWEEN 1 AND 10", name="ck_jobs_attempts"),
        Index("ix_jobs_ready", "state", "available_at", "id"),
        Index("ix_jobs_expired_lease", "lease_expires_at"),
    )


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    org_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    sequence: Mapped[int] = mapped_column(BigInteger, nullable=False)
    actor_id: Mapped[UUID | None] = mapped_column(PGUUID(as_uuid=True))
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    object_type: Mapped[str] = mapped_column(String(100), nullable=False)
    object_id: Mapped[UUID | None] = mapped_column(PGUUID(as_uuid=True))
    redacted_details: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    previous_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    event_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (
        ForeignKeyConstraint(["org_id"], ["organizations.id"], ondelete="RESTRICT"),
        UniqueConstraint("org_id", "sequence", name="uq_audit_events_sequence"),
        CheckConstraint(
            "previous_hash ~ '^[0-9a-f]{64}$' AND event_hash ~ '^[0-9a-f]{64}$'",
            name="ck_audit_events_hash",
        ),
        Index("ix_audit_events_org_time", "org_id", "occurred_at"),
    )


class IdempotencyKey(Base):
    __tablename__ = "idempotency_keys"

    org_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    principal_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    route: Mapped[str] = mapped_column(String(200), primary_key=True)
    key: Mapped[str] = mapped_column(String(200), primary_key=True)
    request_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    response_ref: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        ForeignKeyConstraint(["org_id"], ["organizations.id"], ondelete="CASCADE"),
        CheckConstraint("request_digest ~ '^[0-9a-f]{64}$'", name="ck_idempotency_request_digest"),
        Index("ix_idempotency_expiry", "expires_at"),
    )


class User(Base, Timestamped):
    __tablename__ = "users"
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    org_id: Mapped[UUID] = mapped_column(ForeignKey("organizations.id"), nullable=False)
    subject: Mapped[str] = mapped_column(String(255), nullable=False)
    auth_provider: Mapped[str] = mapped_column(String(24), default="local", nullable=False)
    email: Mapped[str] = mapped_column(String(320), nullable=False)
    password_hash: Mapped[str | None] = mapped_column(String(512))
    totp_ciphertext: Mapped[bytes | None] = mapped_column(LargeBinary)
    last_totp_step: Mapped[int] = mapped_column(BigInteger, default=-1, nullable=False)
    recovery_hashes: Mapped[list[str]] = mapped_column(JSONB, default=list, nullable=False)
    disabled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    __table_args__ = (
        UniqueConstraint("org_id", "id", name="uq_users_org_id"),
        UniqueConstraint("org_id", "auth_provider", "subject", name="uq_users_subject"),
    )


class RoleBinding(Base, Timestamped):
    __tablename__ = "role_bindings"
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    org_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    user_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    role: Mapped[str] = mapped_column(String(40), nullable=False)
    site_id: Mapped[UUID | None] = mapped_column(PGUUID(as_uuid=True))
    __table_args__ = (
        ForeignKeyConstraint(["org_id", "user_id"], ["users.org_id", "users.id"]),
        ForeignKeyConstraint(["org_id", "site_id"], ["sites.org_id", "sites.id"]),
        UniqueConstraint(
            "org_id",
            "user_id",
            "role",
            "site_id",
            name="uq_role_bindings_scope",
            postgresql_nulls_not_distinct=True,
        ),
        CheckConstraint(
            "role IN ('viewer','analyst','scan_operator','auditor','manual_assessor',"
            "'policy_author','policy_approver','risk_approver','credential_admin',"
            "'platform_admin','inventory_editor')",
            name="ck_role_bindings_role",
        ),
        CheckConstraint("role <> 'platform_admin' OR site_id IS NULL", name="ck_admin_scope"),
    )


class AuthSession(Base):
    __tablename__ = "sessions"
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    org_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    user_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    token_hash: Mapped[bytes] = mapped_column(LargeBinary, unique=True, nullable=False)
    mfa_verified_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    __table_args__ = (
        ForeignKeyConstraint(["org_id", "user_id"], ["users.org_id", "users.id"]),
        Index("ix_sessions_expiration", "expires_at"),
    )


class AuthChallenge(Base):
    __tablename__ = "auth_challenges"
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    org_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    user_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    token_hash: Mapped[bytes] = mapped_column(LargeBinary, unique=True, nullable=False)
    attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    __table_args__ = (
        ForeignKeyConstraint(["org_id", "user_id"], ["users.org_id", "users.id"]),
        CheckConstraint("attempts BETWEEN 0 AND 5", name="ck_challenge_attempts"),
        Index("ix_auth_challenges_expiration", "expires_at"),
    )


class AuthThrottle(Base):
    __tablename__ = "auth_throttles"
    key_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    window_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False)


# --- Collection/pipeline tables (migration 0004_pipeline) -------------------
# Snapshots, artifacts, evidence, results, findings, exceptions, reviews,
# reports, schedules, credentials and trust records follow PRD section 12.


class Artifact(Base):
    __tablename__ = "artifacts"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    org_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    storage_key: Mapped[str] = mapped_column(String(256), nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    media_type: Mapped[str] = mapped_column(String(100), nullable=False)
    size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    classification: Mapped[str] = mapped_column(String(24), default="redacted", nullable=False)
    encrypted: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("true"))
    key_version: Mapped[str] = mapped_column(String(64), nullable=False)
    retention_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    legal_hold: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (
        UniqueConstraint("org_id", "id", name="uq_artifacts_org_id"),
        ForeignKeyConstraint(["org_id"], ["organizations.id"], ondelete="RESTRICT"),
        UniqueConstraint("org_id", "storage_key", name="uq_artifacts_store_key"),
        CheckConstraint("size_bytes > 0", name="ck_artifacts_size"),
        CheckConstraint("sha256 ~ '^[0-9a-f]{64}$'", name="ck_artifacts_sha256"),
        CheckConstraint(
            "classification IN ('redacted', 'normalized', 'report', 'raw_restricted')",
            name="ck_artifacts_classification",
        ),
        Index("ix_artifacts_org_sha", "org_id", "sha256"),
    )


class Snapshot(Base):
    __tablename__ = "snapshots"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    org_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    target_id: Mapped[UUID | None] = mapped_column(PGUUID(as_uuid=True))
    asset_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    source: Mapped[str] = mapped_column(String(16), nullable=False)
    identity: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    configuration_plane: Mapped[str] = mapped_column(
        String(64), default="effective", nullable=False
    )
    observed_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    observed_end: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    digest: Mapped[str] = mapped_column(String(64), nullable=False)
    completeness: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    provenance: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (
        UniqueConstraint("org_id", "id", name="uq_snapshots_org_id"),
        ForeignKeyConstraint(["org_id", "target_id"], ["scan_targets.org_id", "scan_targets.id"]),
        ForeignKeyConstraint(
            ["org_id", "asset_id"], ["assets.org_id", "assets.id"], ondelete="RESTRICT"
        ),
        CheckConstraint(
            "source IN ('live', 'import', 'replay', 'fixture')", name="ck_snapshots_source"
        ),
        CheckConstraint("digest ~ '^[0-9a-f]{64}$'", name="ck_snapshots_digest"),
        CheckConstraint("observed_end >= observed_start", name="ck_snapshots_observation_order"),
        Index("ix_snapshots_asset_received", "org_id", "asset_id", "received_at"),
        Index("ix_snapshots_digest", "org_id", "digest"),
    )


class EvidenceRef(Base):
    __tablename__ = "evidence_refs"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    org_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    snapshot_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    artifact_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    reader_id: Mapped[str] = mapped_column(String(200), nullable=False)
    pointer: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    redaction_version: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (
        UniqueConstraint("org_id", "id", name="uq_evidence_refs_org_id"),
        ForeignKeyConstraint(
            ["org_id", "snapshot_id"], ["snapshots.org_id", "snapshots.id"], ondelete="CASCADE"
        ),
        ForeignKeyConstraint(
            ["org_id", "artifact_id"], ["artifacts.org_id", "artifacts.id"], ondelete="RESTRICT"
        ),
        Index("ix_evidence_refs_snapshot", "org_id", "snapshot_id"),
    )


class ResultSet(Base):
    __tablename__ = "result_sets"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    org_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    run_id: Mapped[UUID | None] = mapped_column(PGUUID(as_uuid=True))
    target_id: Mapped[UUID | None] = mapped_column(PGUUID(as_uuid=True))
    snapshot_id: Mapped[UUID | None] = mapped_column(PGUUID(as_uuid=True))
    asset_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    policy_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    engine_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    view: Mapped[str] = mapped_column(String(64), default="primary", nullable=False)
    semantic_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    summary: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    replay_of: Mapped[UUID | None] = mapped_column(PGUUID(as_uuid=True))
    completed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (
        UniqueConstraint("org_id", "id", name="uq_result_sets_org_id"),
        ForeignKeyConstraint(["org_id", "run_id"], ["scan_runs.org_id", "scan_runs.id"]),
        ForeignKeyConstraint(["org_id", "target_id"], ["scan_targets.org_id", "scan_targets.id"]),
        ForeignKeyConstraint(["org_id", "snapshot_id"], ["snapshots.org_id", "snapshots.id"]),
        ForeignKeyConstraint(["org_id", "asset_id"], ["assets.org_id", "assets.id"]),
        ForeignKeyConstraint(["org_id", "policy_id"], ["policies.org_id", "policies.id"]),
        ForeignKeyConstraint(["org_id", "replay_of"], ["result_sets.org_id", "result_sets.id"]),
        CheckConstraint("engine_digest ~ '^[0-9a-f]{64}$'", name="ck_result_sets_engine_digest"),
        CheckConstraint(
            "semantic_digest ~ '^[0-9a-f]{64}$'", name="ck_result_sets_semantic_digest"
        ),
        CheckConstraint(
            "view IN ('primary', 'original_profile', 'tailored')", name="ck_result_sets_view"
        ),
        UniqueConstraint(
            "org_id", "run_id", "asset_id", "policy_id", "view", name="uq_result_sets_finalized"
        ),
        Index("ix_result_sets_asset_completed", "org_id", "asset_id", "completed_at"),
    )


class ControlResultRecord(Base):
    __tablename__ = "control_results"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    org_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    result_set_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    control_key: Mapped[str] = mapped_column(String(200), nullable=False)
    control_revision: Mapped[int] = mapped_column(Integer, nullable=False)
    context_key: Mapped[str] = mapped_column(String(200), default="global", nullable=False)
    resource_key: Mapped[str] = mapped_column(String(200), default="__control__", nullable=False)
    status: Mapped[str] = mapped_column(String(24), nullable=False)
    reason_code: Mapped[str] = mapped_column(String(100), nullable=False)
    expected: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    actual: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    assessment_quality: Mapped[str] = mapped_column(String(24), nullable=False)
    trace: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    counts_toward_score: Mapped[bool] = mapped_column(Boolean, nullable=False)
    parent_result_id: Mapped[UUID | None] = mapped_column(PGUUID(as_uuid=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (
        UniqueConstraint("org_id", "id", name="uq_control_results_org_id"),
        ForeignKeyConstraint(
            ["org_id", "result_set_id"],
            ["result_sets.org_id", "result_sets.id"],
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["org_id", "parent_result_id"],
            ["control_results.org_id", "control_results.id"],
        ),
        CheckConstraint(
            "status IN ('PASS', 'FAIL', 'NOT_APPLICABLE', 'UNKNOWN', 'ERROR', 'MANUAL_REQUIRED')",
            name="ck_control_results_status",
        ),
        CheckConstraint(
            "severity IN ('critical', 'high', 'medium', 'low')",
            name="ck_control_results_severity",
        ),
        CheckConstraint(
            "assessment_quality IN ('proven', 'manual_verified', 'incomplete', 'advisory')",
            name="ck_control_results_quality",
        ),
        CheckConstraint(
            "(counts_toward_score = true AND resource_key = '__control__' "
            "AND parent_result_id IS NULL) OR (counts_toward_score = false "
            "AND resource_key <> '__control__' AND parent_result_id IS NOT NULL)",
            name="ck_control_results_granularity",
        ),
        UniqueConstraint(
            "result_set_id",
            "control_key",
            "context_key",
            "resource_key",
            name="uq_control_results_identity",
        ),
        Index("ix_control_results_result_set", "org_id", "result_set_id"),
        Index("ix_control_results_status", "org_id", "status"),
    )


class ResultEvidence(Base):
    __tablename__ = "result_evidence"

    org_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    result_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    evidence_ref_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)

    __table_args__ = (
        ForeignKeyConstraint(
            ["org_id", "result_id"],
            ["control_results.org_id", "control_results.id"],
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["org_id", "evidence_ref_id"], ["evidence_refs.org_id", "evidence_refs.id"]
        ),
    )


class Finding(Base, Timestamped):
    __tablename__ = "findings"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    org_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    asset_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    control_key: Mapped[str] = mapped_column(String(200), nullable=False)
    control_revision: Mapped[int] = mapped_column(Integer, nullable=False)
    context_key: Mapped[str] = mapped_column(String(200), default="global", nullable=False)
    resource_key: Mapped[str] = mapped_column(String(200), nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    state: Mapped[str] = mapped_column(String(24), nullable=False)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_result_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    owner_id: Mapped[UUID | None] = mapped_column(PGUUID(as_uuid=True))
    due_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        UniqueConstraint("org_id", "id", name="uq_findings_org_id"),
        ForeignKeyConstraint(
            ["org_id", "asset_id"], ["assets.org_id", "assets.id"], ondelete="RESTRICT"
        ),
        ForeignKeyConstraint(
            ["org_id", "owner_id"], ["users.org_id", "users.id"], ondelete="RESTRICT"
        ),
        ForeignKeyConstraint(
            ["org_id", "last_result_id"],
            ["control_results.org_id", "control_results.id"],
        ),
        CheckConstraint("state IN ('OPEN', 'RESOLVED', 'RISK_ACCEPTED')", name="ck_findings_state"),
        CheckConstraint(
            "severity IN ('critical', 'high', 'medium', 'low')", name="ck_findings_severity"
        ),
        UniqueConstraint(
            "org_id",
            "asset_id",
            "control_key",
            "context_key",
            "resource_key",
            name="uq_findings_stable_key",
        ),
        Index("ix_findings_state", "org_id", "state", "severity"),
        Index("ix_findings_owner", "org_id", "owner_id"),
    )


class FindingEvent(Base):
    __tablename__ = "finding_events"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    org_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    finding_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    kind: Mapped[str] = mapped_column(String(64), nullable=False)
    actor_id: Mapped[UUID | None] = mapped_column(PGUUID(as_uuid=True))
    result_id: Mapped[UUID | None] = mapped_column(PGUUID(as_uuid=True))
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (
        UniqueConstraint("org_id", "id", name="uq_finding_events_org_id"),
        ForeignKeyConstraint(
            ["org_id", "finding_id"], ["findings.org_id", "findings.id"], ondelete="CASCADE"
        ),
        CheckConstraint(
            "kind IN ('OPENED', 'STILL_FAILING', 'FIXED_VERIFIED', 'CLOSED_NO_LONGER_APPLICABLE', "
            "'ASSIGNED', 'DUE_SET', 'COMMENT', 'EXCEPTION_LINKED', 'MANUAL_REVIEW')",
            name="ck_finding_events_kind",
        ),
        Index("ix_finding_events_finding", "org_id", "finding_id", "occurred_at"),
    )


class ExceptionRecord(Base, Timestamped):
    __tablename__ = "exceptions"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    org_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    asset_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    control_key: Mapped[str] = mapped_column(String(200), nullable=False)
    reason: Mapped[str] = mapped_column(String(2000), nullable=False)
    compensating_controls: Mapped[str] = mapped_column(String(2000), nullable=False)
    requested_by: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    approved_by: Mapped[UUID | None] = mapped_column(PGUUID(as_uuid=True))
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    state: Mapped[str] = mapped_column(String(24), nullable=False)

    __table_args__ = (
        UniqueConstraint("org_id", "id", name="uq_exceptions_org_id"),
        ForeignKeyConstraint(
            ["org_id", "asset_id"], ["assets.org_id", "assets.id"], ondelete="RESTRICT"
        ),
        ForeignKeyConstraint(
            ["org_id", "requested_by"], ["users.org_id", "users.id"], ondelete="RESTRICT"
        ),
        ForeignKeyConstraint(
            ["org_id", "approved_by"], ["users.org_id", "users.id"], ondelete="RESTRICT"
        ),
        CheckConstraint(
            "state IN ('REQUESTED', 'APPROVED', 'REVOKED', 'REJECTED')",
            name="ck_exceptions_state",
        ),
        CheckConstraint("expires_at > created_at", name="ck_exceptions_expiry_future"),
        CheckConstraint(
            "state <> 'APPROVED' OR approved_by IS NOT NULL",
            name="ck_exceptions_approved_has_approver",
        ),
        Index("ix_exceptions_expiry", "org_id", "state", "expires_at"),
        Index("ix_exceptions_asset_control", "org_id", "asset_id", "control_key"),
    )


class ManualReview(Base):
    __tablename__ = "manual_reviews"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    org_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    result_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    decision: Mapped[str] = mapped_column(String(40), nullable=False)
    rationale: Mapped[str] = mapped_column(String(2000), nullable=False)
    evidence_refs: Mapped[list[str]] = mapped_column(JSONB, default=list, nullable=False)
    reviewer_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    supersedes_id: Mapped[UUID | None] = mapped_column(PGUUID(as_uuid=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (
        UniqueConstraint("org_id", "id", name="uq_manual_reviews_org_id"),
        ForeignKeyConstraint(
            ["org_id", "result_id"], ["control_results.org_id", "control_results.id"]
        ),
        ForeignKeyConstraint(
            ["org_id", "reviewer_id"], ["users.org_id", "users.id"], ondelete="RESTRICT"
        ),
        ForeignKeyConstraint(
            ["org_id", "supersedes_id"], ["manual_reviews.org_id", "manual_reviews.id"]
        ),
        CheckConstraint(
            "decision IN ('CONFIRMED_PASS', 'CONFIRMED_FAIL', 'REJECTED_ASSESSMENT')",
            name="ck_manual_reviews_decision",
        ),
        Index("ix_manual_reviews_result", "org_id", "result_id"),
    )


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    org_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    requested_by: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    run_id: Mapped[UUID | None] = mapped_column(PGUUID(as_uuid=True))
    format: Mapped[str] = mapped_column(String(16), nullable=False)
    scope_manifest: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    cutoff_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    state: Mapped[str] = mapped_column(String(24), default="QUEUED", nullable=False)
    artifact_id: Mapped[UUID | None] = mapped_column(PGUUID(as_uuid=True))
    manifest_digest: Mapped[str | None] = mapped_column(String(64))
    error_code: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (
        UniqueConstraint("org_id", "id", name="uq_reports_org_id"),
        ForeignKeyConstraint(
            ["org_id", "requested_by"], ["users.org_id", "users.id"], ondelete="RESTRICT"
        ),
        ForeignKeyConstraint(["org_id", "run_id"], ["scan_runs.org_id", "scan_runs.id"]),
        ForeignKeyConstraint(["org_id", "artifact_id"], ["artifacts.org_id", "artifacts.id"]),
        CheckConstraint("format IN ('json', 'html', 'csv', 'pdf')", name="ck_reports_format"),
        CheckConstraint(
            "state IN ('QUEUED', 'RENDERING', 'COMPLETED', 'FAILED')", name="ck_reports_state"
        ),
        CheckConstraint(
            "state <> 'COMPLETED' OR artifact_id IS NOT NULL", name="ck_reports_completed_artifact"
        ),
        Index("ix_reports_org_created", "org_id", "created_at"),
    )


class Schedule(Base, Timestamped):
    __tablename__ = "schedules"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    org_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    site_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    policy_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    cron: Mapped[str] = mapped_column(String(100), nullable=False)
    timezone: Mapped[str] = mapped_column(String(100), nullable=False)
    overlap_policy: Mapped[str] = mapped_column(String(16), default="skip", nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("true"))
    created_by: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)

    __table_args__ = (
        UniqueConstraint("org_id", "id", name="uq_schedules_org_id"),
        ForeignKeyConstraint(["org_id", "site_id"], ["sites.org_id", "sites.id"]),
        ForeignKeyConstraint(["org_id", "policy_id"], ["policies.org_id", "policies.id"]),
        ForeignKeyConstraint(["org_id", "created_by"], ["users.org_id", "users.id"]),
        UniqueConstraint("org_id", "name", name="uq_schedules_name"),
        CheckConstraint("overlap_policy IN ('skip', 'reschedule')", name="ck_schedules_overlap"),
        Index("ix_schedules_enabled", "org_id", "enabled"),
    )


class ScheduleOccurrence(Base):
    __tablename__ = "schedule_occurrences"

    org_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    schedule_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    occurrence_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), primary_key=True)
    status: Mapped[str] = mapped_column(String(16), default="ENQUEUED", nullable=False)
    run_id: Mapped[UUID | None] = mapped_column(PGUUID(as_uuid=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (
        ForeignKeyConstraint(
            ["org_id", "schedule_id"], ["schedules.org_id", "schedules.id"], ondelete="CASCADE"
        ),
        ForeignKeyConstraint(["org_id", "run_id"], ["scan_runs.org_id", "scan_runs.id"]),
        CheckConstraint(
            "status IN ('ENQUEUED', 'COMPLETED', 'SKIPPED')", name="ck_occurrence_status"
        ),
    )


class Credential(Base, Timestamped):
    __tablename__ = "credentials"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    org_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    kind: Mapped[str] = mapped_column(String(24), nullable=False)
    encrypted_secret: Mapped[bytes | None] = mapped_column(LargeBinary)
    key_version: Mapped[str] = mapped_column(String(64), nullable=False)
    credential_metadata: Mapped[dict[str, Any]] = mapped_column(
        "metadata", JSONB, default=dict, nullable=False
    )
    created_by: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)

    __table_args__ = (
        UniqueConstraint("org_id", "id", name="uq_credentials_org_id"),
        ForeignKeyConstraint(
            ["org_id", "created_by"], ["users.org_id", "users.id"], ondelete="RESTRICT"
        ),
        UniqueConstraint("org_id", "name", name="uq_credentials_name"),
        CheckConstraint(
            "kind IN ('ssh_key', 'ssh_password', 'api_token')", name="ck_credentials_kind"
        ),
        CheckConstraint(
            "encrypted_secret IS NOT NULL OR metadata ? 'external_ref'",
            name="ck_credentials_material_or_ref",
        ),
        Index("ix_credentials_org_kind", "org_id", "kind"),
    )


class AssetCredential(Base):
    __tablename__ = "asset_credentials"

    org_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    asset_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    credential_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    purpose: Mapped[str] = mapped_column(String(40), primary_key=True)

    __table_args__ = (
        ForeignKeyConstraint(
            ["org_id", "asset_id"], ["assets.org_id", "assets.id"], ondelete="CASCADE"
        ),
        ForeignKeyConstraint(
            ["org_id", "credential_id"],
            ["credentials.org_id", "credentials.id"],
            ondelete="CASCADE",
        ),
        CheckConstraint(
            "purpose IN ('audit_collect', 'preflight')", name="ck_asset_credentials_purpose"
        ),
    )


class AssetTrust(Base, Timestamped):
    __tablename__ = "asset_trust"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    org_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    asset_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    trust_type: Mapped[str] = mapped_column(String(40), nullable=False)
    fingerprint: Mapped[str] = mapped_column(String(256), nullable=False)
    verified_by: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    verified_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        UniqueConstraint("org_id", "id", name="uq_asset_trust_org_id"),
        ForeignKeyConstraint(
            ["org_id", "asset_id"], ["assets.org_id", "assets.id"], ondelete="CASCADE"
        ),
        ForeignKeyConstraint(
            ["org_id", "verified_by"], ["users.org_id", "users.id"], ondelete="RESTRICT"
        ),
        CheckConstraint(
            "trust_type IN ('ssh_host_key', 'tls_certificate')", name="ck_asset_trust_type"
        ),
        Index(
            "uq_asset_trust_active_fingerprint",
            "org_id",
            "asset_id",
            "trust_type",
            "fingerprint",
            unique=True,
            postgresql_where=text("revoked_at IS NULL"),
        ),
    )


class IntentRecord(Base, Timestamped):
    __tablename__ = "intent_records"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    org_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    asset_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    resource_key: Mapped[str] = mapped_column(String(200), nullable=False)
    kind: Mapped[str] = mapped_column(String(40), nullable=False)
    value: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    approved_by: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        UniqueConstraint("org_id", "id", name="uq_intent_records_org_id"),
        ForeignKeyConstraint(
            ["org_id", "asset_id"], ["assets.org_id", "assets.id"], ondelete="CASCADE"
        ),
        ForeignKeyConstraint(
            ["org_id", "approved_by"], ["users.org_id", "users.id"], ondelete="RESTRICT"
        ),
        CheckConstraint("kind IN ('port_purpose')", name="ck_intent_records_kind"),
        Index("ix_intent_records_asset", "org_id", "asset_id", "resource_key"),
    )
