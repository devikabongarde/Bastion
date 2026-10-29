"""Typed contracts for the collection/evaluation/finding/report pipeline."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal, Self
from uuid import UUID

from pydantic import Field, model_validator

from baselineguard_contracts.common import Contract, FactState, ResultStatus

FindingState = Literal["OPEN", "RESOLVED", "RISK_ACCEPTED"]
ReviewDecision = Literal["CONFIRMED_PASS", "CONFIRMED_FAIL", "REJECTED_ASSESSMENT"]
ReportFormat = Literal["json", "html", "csv", "pdf"]


class FactInput(Contract):
    """Declarative fact supplied through an offline import bundle."""

    state: FactState = FactState.PRESENT
    value: Any | None = None
    unit: str | None = Field(default=None, max_length=32)


class ImportBundle(Contract):
    """FR-04 offline input: declared, hash-verified, provenance-attested facts.

    Uploaded data can never masquerade as freshly collected live evidence;
    the server stamps `source = import` and records the uploader identity.
    """

    asset_id: UUID
    adapter_id: str = Field(min_length=1, max_length=100)
    declared_identity: dict[str, Any]
    observed_start: datetime
    observed_end: datetime
    capture_attested: bool = True
    attested_by: str | None = Field(default=None, max_length=200)
    provably_complete: dict[str, str] = Field(default_factory=dict)
    facts: dict[str, FactInput] = Field(min_length=1)
    raw_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def _check_bounds(self) -> Self:
        if self.observed_end < self.observed_start:
            raise ValueError("observed_end must not precede observed_start")
        for key in self.facts:
            if len(key) > 200 or not key.replace(".", "").replace("_", "").isalnum():
                raise ValueError(f"fact key looks irregular: {key!r}")
        return self


class ImportedSnapshot(Contract):
    snapshot_id: UUID
    asset_id: UUID
    digest: str
    source: str
    received_at: datetime
    freshness: str


class ControlResultRead(Contract):
    result_id: UUID
    result_set_id: UUID
    control_key: str
    control_revision: int
    status: ResultStatus
    reason_code: str
    context_key: str
    resource_key: str
    counts_toward_score: bool
    parent_result_id: UUID | None = None
    expected: dict[str, Any]
    actual: dict[str, Any] | None = None
    severity: str
    assessment_quality: str
    evidence: list[dict[str, Any]] = Field(default_factory=lambda: list[dict[str, Any]]())
    exception_state: str | None = None


class FindingRead(Contract):
    id: UUID
    asset_id: UUID
    asset_name: str
    site_id: UUID
    control_key: str
    control_revision: int
    title: str
    severity: str
    state: FindingState
    first_seen_at: datetime
    last_seen_at: datetime
    owner_id: UUID | None = None
    owner_email: str | None = None
    due_at: datetime | None = None
    last_status: str | None = None
    exception_state: str | None = None


class FindingDetail(FindingRead):
    events: list[dict[str, Any]] = Field(default_factory=lambda: list[dict[str, Any]]())
    last_result: ControlResultRead | None = None
    remediation: dict[str, Any] | None = None


class FindingPatch(Contract):
    owner_id: UUID | None = None
    due_at: datetime | None = None
    comment: str | None = Field(default=None, max_length=2000)

    @model_validator(mode="after")
    def _non_empty(self) -> Self:
        if self.owner_id is None and self.due_at is None and self.comment is None:
            raise ValueError("at least one assignment field is required")
        return self


class ExceptionCreate(Contract):
    asset_id: UUID
    control_key: str = Field(min_length=3, max_length=200)
    reason: str = Field(min_length=10, max_length=2000)
    compensating_controls: str = Field(min_length=10, max_length=2000)
    expires_at: datetime

    @model_validator(mode="after")
    def _bounded_expiry(self) -> Self:
        # Bounded scope: an exception cannot be approved for longer than one year.
        if self.expires_at.tzinfo is None:
            raise ValueError("expires_at must include a timezone offset")
        from datetime import UTC  # noqa: PLC0415

        delta_days = (self.expires_at.astimezone(UTC) - datetime.now(UTC)).days
        if delta_days > 366:
            raise ValueError("exception expiry must be within one year of the request")
        if delta_days < 0:
            raise ValueError("expires_at must be in the future")
        return self


class ExceptionRead(Contract):
    id: UUID
    asset_id: UUID
    asset_name: str
    control_key: str
    reason: str
    compensating_controls: str
    requested_by: UUID
    requester_email: str
    approved_by: UUID | None = None
    approver_email: str | None = None
    approved_at: datetime | None = None
    expires_at: datetime
    state: str
    effective_state: str


class ReviewCreate(Contract):
    decision: ReviewDecision
    rationale: str = Field(min_length=10, max_length=2000)
    evidence_ids: list[UUID] = Field(default_factory=lambda: list[UUID](), max_length=20)
    expires_at: datetime


class ReviewRead(Contract):
    id: UUID
    result_id: UUID
    decision: str
    rationale: str
    reviewer_id: UUID
    created_at: datetime
    expires_at: datetime


class ReportCreate(Contract):
    run_id: UUID | None = None
    format: ReportFormat
    policy_revision_id: UUID | None = None
    asset_ids: list[UUID] = Field(default_factory=lambda: list[UUID](), max_length=500)
    evidence_level: Literal["summary", "standard", "full"] = "standard"


class ReportRead(Contract):
    id: UUID
    format: str
    state: str
    scope_summary: dict[str, Any]
    cutoff_at: datetime
    created_at: datetime
    artifact_id: UUID | None = None
    manifest_digest: str | None = None
    error_code: str | None = None


class DownloadLink(Contract):
    url: str
    token: str
    expires_at: datetime


class ScheduleCreate(Contract):
    site_id: UUID
    policy_id: UUID
    name: str = Field(min_length=1, max_length=255)
    cron: str = Field(min_length=9, max_length=100)
    timezone: str = Field(min_length=1, max_length=100)
    overlap_policy: Literal["skip", "reschedule"] = "skip"


class ScheduleRead(Contract):
    id: UUID
    name: str
    site_id: UUID
    policy_id: UUID
    cron: str
    timezone: str
    overlap_policy: str
    enabled: bool
    last_occurrence_at: datetime | None = None
    next_occurrence_at: datetime | None = None


class SecretBody(Contract):
    username: str = Field(min_length=1, max_length=100)
    private_key_pem: str | None = None
    private_key_passphrase: str | None = None
    password: str | None = Field(default=None, max_length=1024)
    token: str | None = Field(default=None, max_length=4096)


class CredentialCreate(Contract):
    name: str = Field(min_length=1, max_length=255)
    kind: Literal["ssh_key", "ssh_password", "api_token"]
    secret: SecretBody | None = None
    external_ref: str | None = Field(default=None, max_length=300)

    @model_validator(mode="after")
    def _material_xor_ref(self) -> Self:
        if self.secret is not None and self.external_ref is not None:
            raise ValueError("provide either inline secret material or an external reference")
        if self.secret is None and self.external_ref is None:
            raise ValueError("secret material or external reference is required")
        return self


class CredentialRead(Contract):
    id: UUID
    name: str
    kind: str
    key_version: str
    created_by: UUID
    username: str | None = None
    has_material: bool
    created_at: datetime


class CredentialBind(Contract):
    credential_id: UUID
    purpose: Literal["audit_collect", "preflight"] = "audit_collect"


class TrustRegister(Contract):
    trust_type: Literal["ssh_host_key", "tls_certificate"]
    fingerprint: str = Field(min_length=16, max_length=256)
    verified_out_of_band: bool = True


class PreflightResult(Contract):
    asset_id: UUID
    reachable: bool | None
    adapter_id: str
    identity: dict[str, Any] | None = None
    required_privileges: list[str] = Field(default_factory=list)
    trust_verified: bool = False
    diagnostics: dict[str, Any] = Field(default_factory=dict)
