from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID, uuid4

from baselineguard_contracts.api import Page, ScanAccepted, ScanCreate
from baselineguard_contracts.policies import PolicySpec
from baselineguard_persistence.models import (
    Asset,
    Job,
    Policy,
    PolicyPack,
    RulePack,
    ScanRun,
    ScanTarget,
)
from fastapi import APIRouter, Depends, Header, Query
from sqlalchemy import desc, select, tuple_, update
from sqlalchemy.orm import Session

from baselineguard_api.audit import append_audit_event
from baselineguard_api.cursors import InvalidCursor, decode_cursor, encode_cursor
from baselineguard_api.dependencies import get_org_db
from baselineguard_api.errors import AppError
from baselineguard_api.idempotency import claim_request, save_response
from baselineguard_api.security import Principal, require_principal

router = APIRouter(tags=["scans"])
PrincipalDep = Annotated[Principal, Depends(require_principal)]
DbDep = Annotated[Session, Depends(get_org_db)]


def _scan_query(principal: Principal, roles: set[str] | None = None):
    statement = select(ScanRun).where(ScanRun.org_id == principal.org_id)
    sites = principal.sites_for(
        roles or {"viewer", "analyst", "scan_operator", "auditor", "platform_admin"}
    )
    if sites is not None:
        if not sites:
            return statement.where(ScanRun.id == UUID(int=0))
        hidden_ids = (
            select(ScanTarget.run_id)
            .join(Asset)
            .where(
                ScanTarget.org_id == principal.org_id,
                Asset.org_id == principal.org_id,
                Asset.site_id.not_in(sites),
            )
        )
        statement = statement.where(ScanRun.id.not_in(hidden_ids))
    return statement


@router.post("/scans", response_model=ScanAccepted, status_code=202)
def create_scan(
    body: ScanCreate,
    principal: PrincipalDep,
    db: DbDep,
    idempotency_key: Annotated[str, Header(alias="Idempotency-Key", min_length=16, max_length=200)],
) -> ScanAccepted:
    if "scan_operator" not in principal.roles:
        raise AppError(
            403, "FORBIDDEN", "Access denied", "You do not have permission for this action."
        )
    route_key = "POST:/api/v1/scans"
    payload = body.model_dump(mode="json")
    replay = claim_request(db, principal, route_key, idempotency_key, payload)
    if replay is not None:
        return ScanAccepted.model_validate(replay)

    policy = db.execute(
        select(Policy).where(
            Policy.org_id == principal.org_id,
            Policy.id == body.policy_revision_id,
            Policy.state == "published",
        )
    ).scalar_one_or_none()
    if policy is None:
        raise AppError(404, "NOT_FOUND", "Not found", "The requested resource is not available.")
    pack_rows = db.execute(
        select(PolicyPack, RulePack)
        .join(
            RulePack,
            (RulePack.org_id == PolicyPack.org_id) & (RulePack.id == PolicyPack.rule_pack_id),
        )
        .where(PolicyPack.org_id == principal.org_id, PolicyPack.policy_id == policy.id)
    ).all()
    if not pack_rows or any(
        link.pack_digest != pack.digest or pack.state != "approved" for link, pack in pack_rows
    ):
        raise AppError(
            409,
            "POLICY_CONTENT_UNAVAILABLE",
            "Policy unavailable",
            "A linked rule pack is missing, revoked, or has changed.",
        )

    assets = (
        db.execute(
            select(Asset)
            .where(
                Asset.org_id == principal.org_id,
                Asset.id.in_(body.asset_ids),
                Asset.archived_at.is_(None),
            )
            .order_by(Asset.id)
        )
        .scalars()
        .all()
    )
    if len(assets) != len(body.asset_ids):
        raise AppError(
            404, "NOT_FOUND", "Not found", "One or more requested resources are not available."
        )
    sites = principal.sites_for({"scan_operator"})
    if sites is not None and any(asset.site_id not in sites for asset in assets):
        raise AppError(
            404, "NOT_FOUND", "Not found", "One or more requested resources are not available."
        )

    created_at = datetime.now(UTC)
    policy_scope = PolicySpec.model_validate(policy.spec).site_ids
    if policy_scope and any(asset.site_id not in policy_scope for asset in assets):
        raise AppError(
            422,
            "POLICY_SCOPE_MISMATCH",
            "Invalid policy scope",
            "The selected baseline does not cover every requested asset's site.",
        )
    run = ScanRun(
        id=uuid4(),
        org_id=principal.org_id,
        policy_id=policy.id,
        requester_id=principal.user_id,
        reason=body.reason,
        status="QUEUED",
        scope_manifest={
            "schema_version": "1.0",
            "policy_revision_id": str(policy.id),
            "policy_revision": policy.revision,
            "policy_digest": policy.digest,
            "rule_packs": [
                {"id": str(pack.id), "version": pack.version, "digest": pack.digest}
                for _, pack in pack_rows
            ],
            "assets": [
                {
                    "id": str(asset.id),
                    "site_id": str(asset.site_id),
                    "adapter_id": asset.adapter_id,
                    "declared_role": asset.declared_role,
                    "identity": asset.identity,
                }
                for asset in assets
            ],
        },
        created_at=created_at,
    )
    db.add(run)
    db.flush()
    targets: list[ScanTarget] = []
    for asset in assets:
        target = ScanTarget(
            id=uuid4(),
            org_id=principal.org_id,
            run_id=run.id,
            asset_id=asset.id,
            context_scope={"root": True},
            frozen_identity=asset.identity or {},
            state="QUEUED",
        )
        db.add(target)
        targets.append(target)
    db.flush()
    for asset, target in zip(assets, targets, strict=True):
        db.add(
            Job(
                id=uuid4(),
                org_id=principal.org_id,
                target_id=target.id,
                kind="COLLECT",
                state="QUEUED",
                attempt=0,
                max_attempts=3,
                payload_ref={
                    "asset_id": str(asset.id),
                    "adapter_id": asset.adapter_id,
                    "policy_id": str(policy.id),
                },
            )
        )
    append_audit_event(
        db,
        principal,
        action="scan.created",
        object_type="scan_run",
        object_id=run.id,
        details={"scan_id": str(run.id), "policy_id": str(policy.id), "target_count": len(assets)},
    )
    accepted = ScanAccepted(
        scan_id=run.id,
        target_count=len(assets),
        policy_revision_id=policy.id,
        created_at=created_at.isoformat(),
    )
    save_response(db, principal, route_key, idempotency_key, accepted.model_dump(mode="json"))
    return accepted


@router.get("/scans", response_model=Page[ScanAccepted])
def list_scans(
    principal: PrincipalDep,
    db: DbDep,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    cursor: Annotated[str | None, Query(max_length=2048)] = None,
) -> Page[ScanAccepted]:
    if not principal.roles.intersection(
        {"viewer", "analyst", "scan_operator", "auditor", "platform_admin"}
    ):
        raise AppError(
            403, "FORBIDDEN", "Access denied", "You do not have permission for this action."
        )
    statement = _scan_query(principal)
    if cursor:
        try:
            created_at, object_id = decode_cursor(cursor, org_id=principal.org_id, route="scans")
        except InvalidCursor:
            raise AppError(
                422,
                "INVALID_CURSOR",
                "Invalid request",
                "The page cursor is invalid or has expired.",
            ) from None
        statement = statement.where(
            tuple_(ScanRun.created_at, ScanRun.id) < tuple_(created_at, object_id)
        )
    rows = (
        db.execute(statement.order_by(desc(ScanRun.created_at), desc(ScanRun.id)).limit(limit + 1))
        .scalars()
        .unique()
        .all()
    )
    has_more = len(rows) > limit
    page = rows[:limit]
    next_cursor = None
    if has_more and page:
        last = page[-1]
        next_cursor = encode_cursor(
            org_id=principal.org_id, route="scans", created_at=last.created_at, object_id=last.id
        )
    items = [
        ScanAccepted(
            scan_id=run.id,
            status=run.status,
            target_count=len(run.scope_manifest.get("assets", [])),
            policy_revision_id=run.policy_id,
            created_at=run.created_at.isoformat(),
        )
        for run in page
    ]
    return Page[ScanAccepted](items=items, next_cursor=next_cursor)


@router.get("/scans/{scan_id}", response_model=ScanAccepted)
def get_scan(scan_id: UUID, principal: PrincipalDep, db: DbDep) -> ScanAccepted:
    if not principal.roles.intersection(
        {"viewer", "analyst", "scan_operator", "auditor", "platform_admin"}
    ):
        raise AppError(
            403, "FORBIDDEN", "Access denied", "You do not have permission for this action."
        )
    run = (
        db.execute(_scan_query(principal).where(ScanRun.id == scan_id))
        .scalars()
        .unique()
        .one_or_none()
    )
    if run is None:
        raise AppError(404, "NOT_FOUND", "Not found", "The requested resource is not available.")
    return ScanAccepted(
        scan_id=run.id,
        status=run.status,
        target_count=len(run.scope_manifest.get("assets", [])),
        policy_revision_id=run.policy_id,
        created_at=run.created_at.isoformat(),
    )


@router.post("/scans/{scan_id}/cancel", response_model=ScanAccepted, status_code=202)
def cancel_scan(scan_id: UUID, principal: PrincipalDep, db: DbDep) -> ScanAccepted:
    """Cancel pending work and fence running workers from acknowledging their result."""
    if "scan_operator" not in principal.roles:
        raise AppError(
            403, "FORBIDDEN", "Access denied", "You do not have permission for this action."
        )
    run = (
        db.execute(
            _scan_query(principal, {"scan_operator"}).where(ScanRun.id == scan_id).with_for_update()
        )
        .scalars()
        .unique()
        .one_or_none()
    )
    if run is None:
        raise AppError(404, "NOT_FOUND", "Not found", "The requested resource is not available.")
    if run.status == "CANCELLED":
        return ScanAccepted(
            scan_id=run.id,
            status=run.status,
            target_count=len(run.scope_manifest.get("assets", [])),
            policy_revision_id=run.policy_id,
            created_at=run.created_at.isoformat(),
        )
    cancellable_statuses = {
        "QUEUED",
        "PREFLIGHT",
        "COLLECTING",
        "NORMALIZING",
        "EVALUATING",
        "RETRY_WAIT",
    }
    if run.status not in cancellable_statuses:
        raise AppError(
            409, "SCAN_NOT_CANCELLABLE", "Request conflict", "This assessment is already terminal."
        )

    now = datetime.now(UTC)
    target_ids = select(ScanTarget.id).where(
        ScanTarget.org_id == principal.org_id, ScanTarget.run_id == run.id
    )
    db.execute(
        update(Job)
        .where(
            Job.org_id == principal.org_id,
            Job.target_id.in_(target_ids),
            Job.state.in_(("QUEUED", "RUNNING", "RETRY_WAIT")),
        )
        .values(
            state="CANCELLED",
            cancel_requested_at=now,
            lease_owner=None,
            lease_token=None,
            lease_expires_at=None,
        )
    )
    db.execute(
        update(ScanTarget)
        .where(
            ScanTarget.org_id == principal.org_id,
            ScanTarget.run_id == run.id,
            ScanTarget.state.in_(
                ("QUEUED", "PREFLIGHT", "COLLECTING", "NORMALIZING", "EVALUATING", "RETRY_WAIT")
            ),
        )
        .values(state="CANCELLED", finished_at=now)
    )
    run.status = "CANCELLED"
    run.finished_at = now
    append_audit_event(
        db,
        principal,
        action="scan.cancelled",
        object_type="scan_run",
        object_id=run.id,
        details={"scan_id": str(run.id)},
    )
    return ScanAccepted(
        scan_id=run.id,
        status=run.status,
        target_count=len(run.scope_manifest.get("assets", [])),
        policy_revision_id=run.policy_id,
        created_at=run.created_at.isoformat(),
    )
