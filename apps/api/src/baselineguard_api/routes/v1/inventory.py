import csv
import io
from datetime import UTC, datetime
from ipaddress import ip_address, ip_network
from typing import Annotated
from uuid import UUID, uuid4

from baselineguard_contracts.api import AssetCreate, AssetRead, Page, SiteCreate, SiteRead
from baselineguard_contracts.common import PlatformIdentity
from baselineguard_persistence.models import Asset, AssetCredential, AssetTrust, Site
from fastapi import APIRouter, Depends, Header, Query, Response
from pydantic import BaseModel, Field
from sqlalchemy import desc, select, tuple_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from baselineguard_api.audit import append_audit_event
from baselineguard_api.cursors import InvalidCursor, decode_cursor, encode_cursor
from baselineguard_api.dependencies import get_org_db
from baselineguard_api.errors import AppError
from baselineguard_api.idempotency import claim_request, save_response
from baselineguard_api.security import Principal, require_principal

router = APIRouter(tags=["inventory"])
PrincipalDep = Annotated[Principal, Depends(require_principal)]
DbDep = Annotated[Session, Depends(get_org_db)]
READ_ROLES = {"viewer", "analyst", "scan_operator", "auditor", "inventory_editor", "platform_admin"}


def _require_role(principal: Principal, allowed: set[str]) -> None:
    if not principal.roles.intersection(allowed):
        raise AppError(
            403, "FORBIDDEN", "Access denied", "You do not have permission for this action."
        )


def _site_query(principal: Principal):
    statement = select(Site).where(Site.org_id == principal.org_id)
    sites = principal.sites_for(READ_ROLES)
    if sites is not None:
        if not sites:
            return statement.where(Site.id == UUID(int=0))
        statement = statement.where(Site.id.in_(sites))
    return statement


def _asset_query(principal: Principal, roles: set[str] = READ_ROLES):
    statement = select(Asset).where(Asset.org_id == principal.org_id, Asset.archived_at.is_(None))
    sites = principal.sites_for(roles)
    if sites is not None:
        if not sites:
            return statement.where(Asset.site_id == UUID(int=0))
        statement = statement.where(Asset.site_id.in_(sites))
    return statement


LIVE_SSH_ADAPTERS = {"linux-ssh", "cisco-iosxe", "fortigate-ssh"}
# Mirrors ck_assets_category in the assets table.
ASSET_CATEGORIES = frozenset({"windows", "linux", "firewall", "router", "switch"})


def collection_mode(adapter_id: str) -> str:
    if adapter_id in LIVE_SSH_ADAPTERS:
        return "live_ssh"
    if adapter_id == "windows-local":
        return "live_local"
    if adapter_id.endswith("-fixture"):
        return "fixture"
    return "import"


def _readiness(db: Session, org_id: UUID, asset_ids: list[UUID]) -> tuple[dict, set]:
    if not asset_ids:
        return {}, set()
    trusts = {
        row.asset_id: row
        for row in db.execute(
            select(AssetTrust).where(
                AssetTrust.org_id == org_id,
                AssetTrust.asset_id.in_(asset_ids),
                AssetTrust.revoked_at.is_(None),
            )
        ).scalars()
    }
    bound = set(
        db.execute(
            select(AssetCredential.asset_id).where(
                AssetCredential.org_id == org_id,
                AssetCredential.asset_id.in_(asset_ids),
                AssetCredential.purpose == "audit_collect",
            )
        ).scalars()
    )
    return trusts, bound


def _to_asset(asset: Asset, trust: AssetTrust | None = None, credential_bound: bool = False) -> AssetRead:
    return AssetRead(
        id=asset.id,
        org_id=asset.org_id,
        site_id=asset.site_id,
        category=asset.category,
        name=asset.name,
        address=asset.address,
        port=asset.port,
        adapter_id=asset.adapter_id,
        declared_role=asset.declared_role,
        identity=PlatformIdentity.model_validate(asset.identity) if asset.identity else None,
        criticality=asset.criticality,
        owner_id=asset.owner_id,
        tags=asset.tags,
        archived_at=asset.archived_at.isoformat() if asset.archived_at else None,
        collection_mode=collection_mode(asset.adapter_id),
        host_key_fingerprint=trust.fingerprint if trust else None,
        host_key_verified_at=trust.verified_at.isoformat() if trust else None,
        credential_bound=credential_bound,
    )


def _asset_in_scope(asset: AssetCreate, site: Site) -> bool:
    scope = site.scope
    if asset.port not in scope.get("allowed_ports", []):
        return False
    try:
        candidate_ip = ip_address(asset.address)
    except ValueError:
        host = asset.address.lower().rstrip(".")
        suffixes = scope.get("allowed_dns_suffixes", [])
        return any(
            host == suffix.lstrip(".").lower() or host.endswith("." + suffix.lstrip(".").lower())
            for suffix in suffixes
        )
    return any(
        candidate_ip in ip_network(cidr, strict=False) for cidr in scope.get("allowed_cidrs", [])
    )


@router.get("/sites", response_model=Page[SiteRead])
def list_sites(
    principal: PrincipalDep,
    db: DbDep,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    cursor: Annotated[str | None, Query(max_length=2048)] = None,
) -> Page[SiteRead]:
    _require_role(principal, READ_ROLES)
    statement = _site_query(principal)
    if cursor:
        try:
            created_at, object_id = decode_cursor(cursor, org_id=principal.org_id, route="sites")
        except InvalidCursor:
            raise AppError(
                422,
                "INVALID_CURSOR",
                "Invalid request",
                "The page cursor is invalid or has expired.",
            ) from None
        statement = statement.where(
            tuple_(Site.created_at, Site.id) < tuple_(created_at, object_id)
        )
    rows = (
        db.execute(statement.order_by(desc(Site.created_at), desc(Site.id)).limit(limit + 1))
        .scalars()
        .all()
    )
    has_more = len(rows) > limit
    sites = rows[:limit]
    next_cursor = None
    if has_more and sites:
        last = sites[-1]
        next_cursor = encode_cursor(
            org_id=principal.org_id, route="sites", created_at=last.created_at, object_id=last.id
        )
    return Page[SiteRead](
        items=[
            SiteRead(
                id=site.id,
                org_id=site.org_id,
                name=site.name,
                timezone=site.timezone,
                scope=site.scope,
            )
            for site in sites
        ],
        next_cursor=next_cursor,
    )


@router.post("/sites", response_model=SiteRead, status_code=201)
def create_site(
    body: SiteCreate,
    principal: PrincipalDep,
    db: DbDep,
    idempotency_key: Annotated[str, Header(alias="Idempotency-Key", min_length=16, max_length=200)],
) -> SiteRead:
    _require_role(principal, {"platform_admin"})
    payload = body.model_dump(mode="json")
    route_key = "POST:/api/v1/sites"
    replay = claim_request(db, principal, route_key, idempotency_key, payload)
    if replay is not None:
        return SiteRead.model_validate(replay)
    site = Site(id=uuid4(), org_id=principal.org_id, **payload)
    db.add(site)
    db.flush()
    append_audit_event(
        db,
        principal,
        action="site.created",
        object_type="site",
        object_id=site.id,
        details={"site_id": str(site.id)},
    )
    result = SiteRead(
        id=site.id, org_id=site.org_id, name=site.name, timezone=site.timezone, scope=site.scope
    )
    save_response(db, principal, route_key, idempotency_key, result.model_dump(mode="json"))
    return result


@router.get("/assets", response_model=Page[AssetRead])
def list_assets(
    principal: PrincipalDep,
    db: DbDep,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    cursor: Annotated[str | None, Query(max_length=2048)] = None,
    category: Annotated[
        str | None, Query(pattern=r"^(windows|linux|firewall|router|switch)$")
    ] = None,
    site_id: UUID | None = None,
) -> Page[AssetRead]:
    _require_role(principal, READ_ROLES)
    statement = _asset_query(principal)
    if category:
        statement = statement.where(Asset.category == category)
    if site_id:
        if "platform_admin" not in principal.roles and site_id not in principal.site_ids:
            raise AppError(
                404, "NOT_FOUND", "Not found", "The requested resource is not available."
            )
        statement = statement.where(Asset.site_id == site_id)
    if cursor:
        try:
            created_at, object_id = decode_cursor(cursor, org_id=principal.org_id, route="assets")
        except InvalidCursor:
            raise AppError(
                422,
                "INVALID_CURSOR",
                "Invalid request",
                "The page cursor is invalid or has expired.",
            ) from None
        statement = statement.where(
            tuple_(Asset.created_at, Asset.id) < tuple_(created_at, object_id)
        )
    rows = (
        db.execute(statement.order_by(desc(Asset.created_at), desc(Asset.id)).limit(limit + 1))
        .scalars()
        .all()
    )
    has_more = len(rows) > limit
    page = rows[:limit]
    next_cursor = None
    if has_more and page:
        last = page[-1]
        next_cursor = encode_cursor(
            org_id=principal.org_id, route="assets", created_at=last.created_at, object_id=last.id
        )
    trusts, bound = _readiness(db, principal.org_id, [asset.id for asset in page])
    return Page[AssetRead](
        items=[_to_asset(asset, trusts.get(asset.id), asset.id in bound) for asset in page],
        next_cursor=next_cursor,
    )


@router.post("/assets", response_model=AssetRead, status_code=201)
def create_asset(
    body: AssetCreate,
    principal: PrincipalDep,
    db: DbDep,
    idempotency_key: Annotated[str, Header(alias="Idempotency-Key", min_length=16, max_length=200)],
) -> AssetRead:
    _require_role(principal, {"inventory_editor", "platform_admin"})
    payload = body.model_dump(mode="json")
    route_key = "POST:/api/v1/assets"
    replay = claim_request(db, principal, route_key, idempotency_key, payload)
    if replay is not None:
        return AssetRead.model_validate(replay)
    site = db.execute(
        select(Site).where(Site.org_id == principal.org_id, Site.id == body.site_id)
    ).scalar_one_or_none()
    sites = principal.sites_for({"inventory_editor", "platform_admin"})
    if site is None or (sites is not None and site.id not in sites):
        raise AppError(404, "NOT_FOUND", "Not found", "The requested resource is not available.")
    if not _asset_in_scope(body, site):
        raise AppError(
            422,
            "ASSET_OUTSIDE_SITE_SCOPE",
            "Invalid target",
            "The address or management port is outside the site's approved scope.",
        )
    asset = Asset(id=uuid4(), org_id=principal.org_id, **payload)
    db.add(asset)
    try:
        db.flush()
    except IntegrityError:
        raise AppError(
            409,
            "ASSET_ALREADY_EXISTS",
            "Request conflict",
            "An active asset already uses this endpoint.",
        ) from None
    append_audit_event(
        db,
        principal,
        action="asset.created",
        object_type="asset",
        object_id=asset.id,
        details={"asset_id": str(asset.id), "site_id": str(site.id), "category": asset.category},
    )
    result = _to_asset(asset)
    save_response(db, principal, route_key, idempotency_key, result.model_dump(mode="json"))
    return result


@router.post("/assets/{asset_id}/archive", status_code=204)
def archive_asset(asset_id: UUID, principal: PrincipalDep, db: DbDep) -> Response:
    _require_role(principal, {"inventory_editor", "platform_admin"})
    asset = db.execute(
        _asset_query(principal, {"inventory_editor", "platform_admin"})
        .where(Asset.id == asset_id)
        .with_for_update()
    ).scalar_one_or_none()
    if asset is None:
        raise AppError(404, "NOT_FOUND", "Not found", "The requested resource is not available.")
    asset.archived_at = datetime.now(UTC)
    asset.row_version += 1
    append_audit_event(
        db,
        principal,
        action="asset.archived",
        object_type="asset",
        object_id=asset.id,
        details={"asset_id": str(asset.id)},
    )
    return Response(status_code=204)


# --- FR-01: CSV Asset Import Preview and Batch Commit -----------------------


class AssetCsvImportPreviewRequest(BaseModel):
    csv_text: str = Field(..., max_length=500_000)
    default_site_id: UUID | None = None


class AssetCsvPreviewRow(BaseModel):
    row_index: int
    name: str
    address: str
    port: int = 22
    category: str = "linux"
    criticality: str = "normal"
    declared_role: str = "server"
    adapter_id: str = "linux-ssh"
    site_id: UUID | None = None
    site_name: str | None = None
    valid: bool
    errors: list[str]


class AssetCsvPreviewResponse(BaseModel):
    total_rows: int
    valid_rows: int
    invalid_rows: int
    rows: list[AssetCsvPreviewRow]


class AssetCsvCommitRow(BaseModel):
    name: str
    address: str
    port: int = 22
    category: str = "linux"
    criticality: str = "normal"
    declared_role: str = "server"
    adapter_id: str = "linux-ssh"
    site_id: UUID
    tags: dict[str, str] = Field(default_factory=dict)


class AssetCsvCommitRequest(BaseModel):
    rows: list[AssetCsvCommitRow]


class AssetCsvCommitResponse(BaseModel):
    created_count: int
    created_ids: list[UUID]


@router.post("/assets/import-preview", response_model=AssetCsvPreviewResponse)
def preview_asset_csv(
    body: AssetCsvImportPreviewRequest,
    principal: PrincipalDep,
    db: DbDep,
) -> AssetCsvPreviewResponse:
    _require_role(principal, {"inventory_editor", "platform_admin"})

    sites = db.execute(_site_query(principal)).scalars().all()
    site_by_id = {s.id: s for s in sites}
    site_by_name = {s.name.strip().lower(): s for s in sites}

    # Fetch existing active assets to check address/name conflicts
    existing_assets = db.execute(
        select(Asset.name, Asset.address, Asset.site_id)
        .where(Asset.org_id == principal.org_id, Asset.archived_at.is_(None))
    ).all()
    existing_combos = {(a[0].lower(), a[2]) for a in existing_assets}
    existing_addrs = {a[1].lower() for a in existing_assets}

    reader = csv.DictReader(io.StringIO(body.csv_text.strip()))
    if not reader.fieldnames:
        raise AppError(422, "EMPTY_CSV", "Invalid CSV", "CSV must contain a header row.")

    # Normalize header mapping
    header_map = {fn.strip().lower(): fn for fn in reader.fieldnames}
    if "name" not in header_map or "address" not in header_map:
        raise AppError(
            422,
            "MISSING_CSV_COLUMNS",
            "Invalid CSV format",
            "CSV must contain at least 'name' and 'address' columns.",
        )

    parsed_rows: list[AssetCsvPreviewRow] = []
    seen_names: set[tuple[str, UUID | None]] = set()
    seen_addrs: set[str] = set()

    for idx, row in enumerate(reader, start=1):
        errors: list[str] = []
        name = row.get(header_map.get("name", ""), "").strip()
        address = row.get(header_map.get("address", ""), "").strip()
        port_raw = row.get(header_map.get("port", ""), "").strip()
        category = row.get(header_map.get("category", ""), "").strip().lower() or "linux"
        if category == "network":  # accepted alias from earlier templates
            category = "switch"
        criticality = row.get(header_map.get("criticality", ""), "").strip().lower() or "normal"
        role = row.get(header_map.get("declared_role", "") or header_map.get("role", ""), "").strip().lower() or "server"
        adapter = row.get(header_map.get("adapter_id", "") or header_map.get("adapter", ""), "").strip().lower()
        if not adapter:
            adapter = {
                "windows": "windows-local",
                "router": "cisco-iosxe",
                "switch": "cisco-iosxe",
                "firewall": "fortigate-ssh",
            }.get(category, "linux-ssh")

        # Determine site
        site_raw = row.get(header_map.get("site", "") or header_map.get("site_name", "") or header_map.get("site_id", ""), "").strip()
        site: Site | None = None
        if site_raw:
            try:
                suid = UUID(site_raw)
                site = site_by_id.get(suid)
            except ValueError:
                site = site_by_name.get(site_raw.lower())
        if site is None and body.default_site_id is not None:
            site = site_by_id.get(body.default_site_id)

        if not name:
            errors.append("Asset name is required.")
        if not address:
            errors.append("Network address is required.")

        port = 22
        if port_raw:
            try:
                port = int(port_raw)
                if not (1 <= port <= 65535):
                    errors.append(f"Port {port} is out of range 1-65535.")
            except ValueError:
                errors.append(f"Port '{port_raw}' is not an integer.")

        if category not in ASSET_CATEGORIES:
            errors.append(
                f"Category '{category}' must be one of: {', '.join(sorted(ASSET_CATEGORIES))}."
            )
        if criticality not in {"critical", "high", "normal", "low"}:
            errors.append(f"Criticality '{criticality}' must be one of: critical, high, normal, low.")

        if site is None:
            errors.append("Target site is required or unresolvable.")
        else:
            # Check site scope
            scope = site.scope or {}
            allowed_ports = scope.get("allowed_ports", [])
            if allowed_ports and port not in allowed_ports:
                errors.append(f"Port {port} is not in site approved ports: {allowed_ports}.")

        # Check duplicate in batch
        target_site_id = site.id if site else None
        if (name.lower(), target_site_id) in seen_names:
            errors.append(f"Duplicate asset name '{name}' within CSV batch for this site.")
        if address.lower() in seen_addrs:
            errors.append(f"Duplicate address '{address}' within CSV batch.")

        # Check duplicate against DB
        if (name.lower(), target_site_id) in existing_combos:
            errors.append(f"Asset name '{name}' already exists in this site.")
        if address.lower() in existing_addrs:
            errors.append(f"Asset address '{address}' is already registered in active inventory.")

        seen_names.add((name.lower(), target_site_id))
        seen_addrs.add(address.lower())

        parsed_rows.append(
            AssetCsvPreviewRow(
                row_index=idx,
                name=name or f"Row {idx}",
                address=address or "unknown",
                port=port,
                category=category,
                criticality=criticality,
                declared_role=role,
                adapter_id=adapter,
                site_id=site.id if site else None,
                site_name=site.name if site else None,
                valid=len(errors) == 0,
                errors=errors,
            )
        )

    valid_count = sum(1 for r in parsed_rows if r.valid)
    return AssetCsvPreviewResponse(
        total_rows=len(parsed_rows),
        valid_rows=valid_count,
        invalid_rows=len(parsed_rows) - valid_count,
        rows=parsed_rows,
    )


@router.post("/assets/import-commit", response_model=AssetCsvCommitResponse, status_code=201)
def commit_asset_csv(
    body: AssetCsvCommitRequest,
    principal: PrincipalDep,
    db: DbDep,
) -> AssetCsvCommitResponse:
    _require_role(principal, {"inventory_editor", "platform_admin"})
    if not body.rows:
        raise AppError(422, "EMPTY_COMMIT", "No rows", "Commit list is empty.")

    created_ids: list[UUID] = []

    for r in body.rows:
        aid = uuid4()
        asset = Asset(
            id=aid,
            org_id=principal.org_id,
            site_id=r.site_id,
            category=r.category,
            name=r.name,
            address=r.address,
            port=r.port,
            adapter_id=r.adapter_id,
            declared_role=r.declared_role,
            criticality=r.criticality,
            owner_id=principal.user_id,
            tags=r.tags,
            identity={},
        )
        db.add(asset)
        created_ids.append(aid)

    try:
        db.flush()
    except IntegrityError:
        raise AppError(
            409,
            "ASSET_CONFLICT",
            "Conflict on commit",
            "An asset with this name or address already exists in the database.",
        ) from None

    append_audit_event(
        db,
        principal,
        action="asset.bulk_imported",
        object_type="asset",
        object_id=principal.org_id,
        details={"created_count": len(created_ids)},
    )

    return AssetCsvCommitResponse(created_count=len(created_ids), created_ids=created_ids)

