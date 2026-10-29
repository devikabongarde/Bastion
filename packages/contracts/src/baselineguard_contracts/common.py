from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated, Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

Identifier = Annotated[
    str, StringConstraints(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9_.:/-]+$")
]
Sha256 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]


def utc_now() -> datetime:
    return datetime.now(UTC)


class Contract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


class ResultStatus(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    UNKNOWN = "UNKNOWN"
    ERROR = "ERROR"
    MANUAL_REQUIRED = "MANUAL_REQUIRED"


class FactState(StrEnum):
    PRESENT = "PRESENT"
    ABSENT_CONFIRMED = "ABSENT_CONFIRMED"
    UNAVAILABLE = "UNAVAILABLE"
    UNSUPPORTED = "UNSUPPORTED"
    CONFLICT = "CONFLICT"


class EvidencePointer(Contract):
    artifact_sha256: Sha256
    reader_id: Identifier
    pointer: dict[str, Any] = Field(default_factory=dict)
    redaction_version: str = Field(min_length=1, max_length=64)


class NormalizedFact(Contract):
    fact_id: Identifier
    state: FactState
    value: Any | None = None
    unit: str | None = Field(default=None, max_length=32)
    source: EvidencePointer | None = None


class PlatformIdentity(Contract):
    vendor: Identifier
    family: Identifier
    version: str = Field(min_length=1, max_length=128)
    build: str | None = Field(default=None, max_length=128)
    edition: str | None = Field(default=None, max_length=128)
    role: Identifier
    architecture: str | None = Field(default=None, max_length=64)
    stable_device_id: str = Field(min_length=1, max_length=256)
    management_authority: Identifier | None = None
    context_key: Identifier = "global"


class CollectionReaderResult(Contract):
    reader_id: Identifier
    state: str
    duration_ms: int = Field(ge=0)
    output_bytes: int = Field(ge=0)
    truncated: bool = False
    error_code: str | None = Field(default=None, max_length=64)


class CollectionEnvelope(Contract):
    schema_version: str = "1.0"
    asset_id: UUID
    collector_id: UUID
    adapter_id: Identifier
    adapter_version: str
    identity: PlatformIdentity
    observed_start: datetime
    observed_end: datetime
    received_at: datetime
    configuration_plane: Identifier
    source_revision: str | None = Field(default=None, max_length=256)
    readers: tuple[CollectionReaderResult, ...]
    facts: tuple[NormalizedFact, ...]
    artifact_sha256: Sha256
    completeness: dict[str, str]

    def model_post_init(self, __context: Any) -> None:
        if self.observed_end < self.observed_start:
            raise ValueError("observed_end must not precede observed_start")


class ControlResult(Contract):
    schema_version: str = "1.0"
    control_key: Identifier
    status: ResultStatus
    reason_code: Identifier
    context_key: Identifier
    resource_key: Identifier = "__control__"
    counts_toward_score: bool = True
    parent_result_id: UUID | None = None
    expected: dict[str, Any]
    actual: Any | None = None
    severity: str = Field(pattern=r"^(critical|high|medium|low)$")
    evidence: tuple[EvidencePointer, ...] = ()
    assessment_quality: str = Field(pattern=r"^(proven|manual_verified|incomplete|advisory)$")
