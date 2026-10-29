from typing import Literal
from uuid import UUID

from pydantic import Field, StrictBool, StrictInt, StrictStr, field_validator

from baselineguard_contracts.common import Contract, Identifier


class ControlOverride(Contract):
    severity: Literal["critical", "high", "medium", "low"] | None = None
    threshold: StrictInt | StrictBool | StrictStr | None = None
    reason: str = Field(min_length=10, max_length=1000)


class PolicySpec(Contract):
    schema_version: Literal["1.0"] = "1.0"
    site_ids: list[UUID] = Field(default_factory=lambda: list[UUID](), max_length=500)
    overrides: dict[Identifier, ControlOverride] = Field(default_factory=dict, max_length=10000)
    exclusions: dict[Identifier, str] = Field(default_factory=dict, max_length=10000)

    @field_validator("site_ids")
    @classmethod
    def unique_sites(cls, value: list[UUID]) -> list[UUID]:
        if len(value) != len(set(value)):
            raise ValueError("Duplicate site identifiers")
        return sorted(value)

    @field_validator("exclusions")
    @classmethod
    def exclusion_reasons(cls, value: dict[str, str]) -> dict[str, str]:
        if any(not 10 <= len(reason.strip()) <= 1000 for reason in value.values()):
            raise ValueError("Each exclusion needs a reason of 10 through 1000 characters")
        return value


class PolicyDraftCreate(Contract):
    name: str = Field(min_length=1, max_length=255)
    rule_pack_ids: list[UUID] = Field(min_length=1, max_length=50)
    spec: PolicySpec = Field(default_factory=PolicySpec)
    reason: str = Field(min_length=10, max_length=1000)

    @field_validator("rule_pack_ids")
    @classmethod
    def unique_packs(cls, value: list[UUID]) -> list[UUID]:
        if len(value) != len(set(value)):
            raise ValueError("Duplicate rule pack identifiers")
        return sorted(value)


class PolicyDraftPatch(Contract):
    spec: PolicySpec
    reason: str = Field(min_length=10, max_length=1000)


class PolicyPublish(Contract):
    reason: str = Field(min_length=10, max_length=1000)
