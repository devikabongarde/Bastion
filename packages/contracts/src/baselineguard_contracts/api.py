import re
from ipaddress import IPv4Network, IPv6Network, collapse_addresses, ip_address, ip_network
from uuid import UUID

from pydantic import Field, IPvAnyNetwork, field_validator

from baselineguard_contracts.common import Contract, PlatformIdentity


class Problem(Contract):
    type: str = "about:blank"
    title: str = Field(min_length=1, max_length=120)
    status: int = Field(ge=400, le=599)
    code: str = Field(min_length=1, max_length=64)
    detail: str = Field(min_length=1, max_length=1000)
    request_id: str = Field(min_length=1, max_length=64)
    errors: list[dict[str, str]] | None = None


class Page[T](Contract):
    items: list[T]
    next_cursor: str | None = None


class AssetCreate(Contract):
    site_id: UUID
    category: str = Field(pattern=r"^(windows|linux|firewall|router|switch)$")
    name: str = Field(min_length=1, max_length=255)
    address: str = Field(min_length=1, max_length=253)
    port: int = Field(ge=1, le=65535)
    adapter_id: str = Field(min_length=1, max_length=100)
    declared_role: str = Field(min_length=1, max_length=100)
    criticality: str = Field(default="normal", pattern=r"^(critical|high|normal|low)$")
    tags: dict[str, str] = Field(default_factory=dict, max_length=64)

    @field_validator("address")
    @classmethod
    def validate_address(cls, value: str) -> str:
        candidate = value.strip().rstrip(".")
        try:
            ip_address(candidate)
            return candidate
        except ValueError:
            if len(candidate) > 253 or not all(
                label
                and len(label) <= 63
                and label[0] != "-"
                and label[-1] != "-"
                and all(char.isalnum() or char == "-" for char in label)
                for label in candidate.split(".")
            ):
                raise ValueError("address must be an IP address or valid DNS name") from None
            return candidate.encode("idna").decode("ascii").lower()


class AssetRead(Contract):
    id: UUID
    org_id: UUID
    site_id: UUID
    category: str
    name: str
    address: str
    port: int
    adapter_id: str
    declared_role: str
    identity: PlatformIdentity | None = None
    criticality: str
    owner_id: UUID | None = None
    tags: dict[str, str]
    archived_at: str | None = None
    # Real collection readiness, never inferred by the UI.
    collection_mode: str = "import"  # live_ssh | live_local | fixture | import
    host_key_fingerprint: str | None = None
    host_key_verified_at: str | None = None
    credential_bound: bool = False


class ScanCreate(Contract):
    asset_ids: list[UUID] = Field(min_length=1, max_length=500)
    policy_revision_id: UUID
    reason: str = Field(min_length=1, max_length=500)

    @field_validator("asset_ids")
    @classmethod
    def unique_assets(cls, value: list[UUID]) -> list[UUID]:
        if len(set(value)) != len(value):
            raise ValueError("asset_ids must not contain duplicates")
        return value


class ScanAccepted(Contract):
    scan_id: UUID
    status: str = "QUEUED"
    target_count: int = Field(ge=1)
    policy_revision_id: UUID
    created_at: str


class Readiness(Contract):
    status: str


class SiteScope(Contract):
    allowed_cidrs: list[IPvAnyNetwork] = Field(min_length=1, max_length=256)
    allowed_dns_suffixes: list[str] = Field(default_factory=list, max_length=64)
    allowed_ports: list[int] = Field(min_length=1, max_length=128)

    @field_validator("allowed_ports")
    @classmethod
    def unique_valid_ports(cls, value: list[int]) -> list[int]:
        if len(set(value)) != len(value) or any(port < 1 or port > 65535 for port in value):
            raise ValueError("allowed_ports must contain unique ports from 1 through 65535")
        return sorted(value)

    @field_validator("allowed_cidrs")
    @classmethod
    def reject_wildcard_scope(cls, value: list[IPvAnyNetwork]) -> list[IPvAnyNetwork]:
        if any(network.prefixlen == 0 for network in value):
            raise ValueError("a site scope cannot include an unrestricted address range")
        if len(set(value)) != len(value):
            raise ValueError("allowed_cidrs must not contain duplicates")
        family_v4: list[IPv4Network] = []
        family_v6: list[IPv6Network] = []
        for network in value:
            normalized = ip_network(str(network), strict=False)
            if isinstance(normalized, IPv4Network):
                family_v4.append(normalized)
            else:
                family_v6.append(normalized)
        if any(network.prefixlen == 0 for network in collapse_addresses(family_v4)) or any(
            network.prefixlen == 0 for network in collapse_addresses(family_v6)
        ):
            raise ValueError("a site scope cannot combine to an unrestricted address range")
        prohibited = (
            "0.0.0.0/8",
            "127.0.0.0/8",
            "169.254.0.0/16",
            "224.0.0.0/4",
            "255.255.255.255/32",
            "::/128",
            "::1/128",
            "fe80::/10",
            "ff00::/8",
        )
        if any(
            network.overlaps(ip_network(block))
            for network in value
            for block in prohibited
            if network.version == ip_network(block).version
        ):
            raise ValueError(
                "a site scope cannot include loopback, link-local, multicast, "
                "unspecified, or broadcast ranges"
            )
        return value

    @field_validator("allowed_dns_suffixes")
    @classmethod
    def normalize_dns_suffixes(cls, value: list[str]) -> list[str]:
        normalized: list[str] = []
        for suffix in value:
            candidate = suffix.strip().lower().lstrip(".").rstrip(".")
            try:
                candidate = candidate.encode("idna").decode("ascii")
            except UnicodeError:
                raise ValueError("DNS suffix must be a valid hostname suffix") from None
            if len(candidate) > 253 or not re.fullmatch(
                r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*",
                candidate,
            ):
                raise ValueError("DNS suffix must be a valid hostname suffix")
            normalized.append(candidate)
        if len(set(normalized)) != len(normalized):
            raise ValueError("allowed_dns_suffixes must not contain duplicates")
        return normalized


class SiteCreate(Contract):
    name: str = Field(min_length=1, max_length=255)
    timezone: str = Field(min_length=1, max_length=100)
    scope: SiteScope

    @field_validator("timezone")
    @classmethod
    def validate_timezone(cls, value: str) -> str:
        from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

        try:
            ZoneInfo(value)
        except (ZoneInfoNotFoundError, ValueError):
            raise ValueError("timezone must be a valid IANA timezone") from None
        return value


class SiteRead(Contract):
    id: UUID
    org_id: UUID
    name: str
    timezone: str
    scope: dict[str, object]
