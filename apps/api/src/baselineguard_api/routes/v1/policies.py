from datetime import UTC, datetime
from typing import Annotated, Any
from uuid import UUID, uuid4

from baselineguard_contracts.policies import (
    PolicyDraftCreate,
    PolicyDraftPatch,
    PolicyPublish,
    PolicySpec,
)
from baselineguard_persistence.models import (
    Asset,
    ControlResultRecord,
    Policy,
    PolicyPack,
    ResultSet,
    RulePack,
    Site,
)
from baselineguard_rule_engine.canonical import semantic_digest
from fastapi import APIRouter, Depends, Header, Query, Response
from sqlalchemy import cast, desc, func, select, text, tuple_
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Session

from baselineguard_api.audit import append_audit_event
from baselineguard_api.cursors import InvalidCursor, decode_cursor, encode_cursor
from baselineguard_api.dependencies import get_org_db
from baselineguard_api.errors import AppError
from baselineguard_api.idempotency import claim_request, save_response
from baselineguard_api.security import Principal, require_principal, require_recent_mfa

router = APIRouter(tags=["policies"])
PrincipalDep = Annotated[Principal, Depends(require_principal)]
DbDep = Annotated[Session, Depends(get_org_db)]
IDKey = Annotated[str, Header(alias="Idempotency-Key", min_length=16, max_length=200)]
ETag = Annotated[str, Header(alias="If-Match", pattern=r'^"[1-9][0-9]*"$')]
READ_ROLES = {
    "viewer",
    "analyst",
    "scan_operator",
    "auditor",
    "policy_author",
    "policy_approver",
    "platform_admin",
}


def _role(principal: Principal, roles: set[str]) -> None:
    if not principal.roles.intersection(roles):
        raise AppError(
            403, "FORBIDDEN", "Access denied", "You do not have permission for this action."
        )


def _scope(principal: Principal, spec: PolicySpec, roles: set[str]) -> None:
    sites = principal.sites_for(roles)
    if sites is not None and (not spec.site_ids or not set(spec.site_ids) <= sites):
        raise AppError(404, "NOT_FOUND", "Not found", "The requested resource is not available.")


def _packs(db: Session, org_id: UUID, policy_id: UUID) -> list[RulePack]:
    return list(
        db.execute(
            select(RulePack)
            .join(
                PolicyPack,
                (PolicyPack.rule_pack_id == RulePack.id) & (PolicyPack.org_id == RulePack.org_id),
            )
            .where(PolicyPack.policy_id == policy_id, PolicyPack.org_id == org_id)
            .order_by(RulePack.pack_key, RulePack.version)
        ).scalars()
    )


def validate_spec(spec: PolicySpec, packs: list[RulePack]) -> dict[str, int]:
    controls: dict[str, Any] = {}
    for pack in packs:
        if pack.state != "approved" or semantic_digest(pack.manifest) != pack.digest:
            raise AppError(
                409,
                "POLICY_CONTENT_UNAVAILABLE",
                "Policy unavailable",
                "A rule pack is unapproved, revoked, or has changed.",
            )
        for control in pack.manifest.get("controls", []):
            key = control["id"]
            if key in controls:
                raise AppError(
                    422,
                    "CONTROL_ID_CONFLICT",
                    "Invalid policy",
                    "Selected packs contain conflicting control identifiers.",
                )
            controls[key] = control
    if not controls:
        raise AppError(
            422, "EMPTY_POLICY", "Invalid policy", "At least one implemented control is required."
        )
    if not (set(spec.overrides) | set(spec.exclusions)) <= set(controls):
        raise AppError(
            422,
            "UNKNOWN_CONTROL",
            "Invalid policy",
            "An override or exclusion refers to an unknown control.",
        )
    for key, override in spec.overrides.items():
        if override.threshold is not None:
            assertion = controls[key]["assertion"]
            if "value" not in assertion or type(override.threshold) is not type(assertion["value"]):
                raise AppError(
                    422,
                    "INVALID_THRESHOLD_TYPE",
                    "Invalid policy",
                    "A threshold must match the source control's scalar type.",
                )
    return {
        "source_controls": len(controls),
        "selected_controls": len(controls) - len(spec.exclusions),
        "excluded_controls": len(spec.exclusions),
        "customized_controls": len(spec.overrides),
    }


def _digest(spec: dict[str, Any], packs: list[RulePack]) -> str:
    return semantic_digest({"spec": spec, "packs": sorted(pack.digest for pack in packs)})


def _read(policy: Policy, packs: list[RulePack]) -> dict[str, Any]:
    spec = PolicySpec.model_validate(policy.spec)
    total = sum(len(pack.manifest.get("controls", [])) for pack in packs)
    return {
        "id": str(policy.id),
        "name": policy.name,
        "revision": policy.revision,
        "state": policy.state,
        "spec": policy.spec,
        "digest": policy.digest,
        "author_id": str(policy.author_id),
        "approver_id": str(policy.approver_id) if policy.approver_id else None,
        "created_at": policy.created_at.isoformat(),
        "published_at": policy.published_at.isoformat() if policy.published_at else None,
        "etag": f'"{policy.row_version}"',
        "coverage": {
            "source_controls": total,
            "selected_controls": total - len(spec.exclusions),
            "excluded_controls": len(spec.exclusions),
            "customized_controls": len(spec.overrides),
        },
        "rule_packs": [
            {
                "id": str(pack.id),
                "pack_key": pack.pack_key,
                "version": pack.version,
                "digest": pack.digest,
                "state": pack.state,
                "rights": pack.rights_metadata,
            }
            for pack in packs
        ],
    }


@router.get("/packs")
def list_packs(
    principal: PrincipalDep,
    db: DbDep,
    limit: int = Query(default=50, ge=1, le=200),
    cursor: str | None = Query(default=None, max_length=2048),
) -> dict[str, Any]:
    _role(principal, READ_ROLES)
    statement = select(RulePack).where(RulePack.org_id == principal.org_id)
    if cursor:
        try:
            timestamp, object_id = decode_cursor(cursor, org_id=principal.org_id, route="packs")
        except InvalidCursor:
            raise AppError(
                422, "INVALID_CURSOR", "Invalid request", "The cursor is invalid or expired."
            ) from None
        statement = statement.where(
            tuple_(RulePack.created_at, RulePack.id) < tuple_(timestamp, object_id)
        )
    rows = list(
        db.execute(
            statement.order_by(RulePack.created_at.desc(), RulePack.id.desc()).limit(limit + 1)
        ).scalars()
    )
    page = rows[:limit]
    return {
        "items": [
            {
                "id": str(pack.id),
                "pack_key": pack.pack_key,
                "version": pack.version,
                "state": pack.state,
                "control_count": len(pack.manifest.get("controls", [])),
                "rights": pack.rights_metadata,
            }
            for pack in page
        ],
        "next_cursor": encode_cursor(
            org_id=principal.org_id,
            route="packs",
            created_at=page[-1].created_at,
            object_id=page[-1].id,
        )
        if len(rows) > limit and page
        else None,
    }


def _policy_query(principal: Principal):
    statement = select(Policy).where(Policy.org_id == principal.org_id)
    sites = principal.sites_for(READ_ROLES)
    if sites is not None:
        if not sites:
            return statement.where(Policy.id == UUID(int=0))
        statement = statement.where(
            func.coalesce(Policy.spec["site_ids"], cast([], JSONB)).op("<@")(
                cast([str(site) for site in sorted(sites)], JSONB)
            )
        )
    return statement


@router.get("/policies")
def list_policies(
    principal: PrincipalDep,
    db: DbDep,
    limit: int = Query(default=50, ge=1, le=200),
    cursor: str | None = Query(default=None, max_length=2048),
) -> dict[str, Any]:
    _role(principal, READ_ROLES)
    statement = _policy_query(principal)
    if cursor:
        try:
            timestamp, object_id = decode_cursor(cursor, org_id=principal.org_id, route="policies")
        except InvalidCursor:
            raise AppError(
                422,
                "INVALID_CURSOR",
                "Invalid request",
                "The page cursor is invalid or has expired.",
            ) from None
        statement = statement.where(
            tuple_(Policy.created_at, Policy.id) < tuple_(timestamp, object_id)
        )
    rows = list(
        db.execute(
            statement.order_by(desc(Policy.created_at), desc(Policy.id)).limit(limit + 1)
        ).scalars()
    )
    page = rows[:limit]
    next_cursor = (
        encode_cursor(
            org_id=principal.org_id,
            route="policies",
            created_at=page[-1].created_at,
            object_id=page[-1].id,
        )
        if len(rows) > limit and page
        else None
    )
    return {
        "items": [_read(policy, _packs(db, principal.org_id, policy.id)) for policy in page],
        "next_cursor": next_cursor,
    }


@router.get("/policies/{policy_id}")
def get_policy(policy_id: UUID, principal: PrincipalDep, db: DbDep, response: Response):
    _role(principal, READ_ROLES)
    policy = db.execute(_policy_query(principal).where(Policy.id == policy_id)).scalar_one_or_none()
    if policy is None:
        raise AppError(404, "NOT_FOUND", "Not found", "The requested resource is not available.")
    response.headers["ETag"] = f'"{policy.row_version}"'
    return _read(policy, _packs(db, principal.org_id, policy.id))


@router.post("/policy-drafts", status_code=201)
def create_draft(
    body: PolicyDraftCreate,
    principal: PrincipalDep,
    db: DbDep,
    response: Response,
    idempotency_key: IDKey,
):
    _role(principal, {"policy_author"})
    _scope(principal, body.spec, {"policy_author"})
    replay = claim_request(
        db, principal, "POST:/policy-drafts", idempotency_key, body.model_dump(mode="json")
    )
    if replay:
        response.headers["ETag"] = str(replay["etag"])
        return replay
    packs = list(
        db.execute(
            select(RulePack).where(
                RulePack.org_id == principal.org_id, RulePack.id.in_(body.rule_pack_ids)
            )
        ).scalars()
    )
    if len(packs) != len(body.rule_pack_ids):
        raise AppError(404, "NOT_FOUND", "Not found", "A requested rule pack is unavailable.")
    if body.spec.site_ids:
        sites = list(
            db.execute(
                select(Site.id).where(
                    Site.org_id == principal.org_id, Site.id.in_(body.spec.site_ids)
                )
            ).scalars()
        )
        if len(sites) != len(body.spec.site_ids):
            raise AppError(404, "NOT_FOUND", "Not found", "A requested site is unavailable.")
    validate_spec(body.spec, packs)
    db.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 1))"),
        {"key": f"{principal.org_id}/{body.name}"},
    )
    revision = (
        db.execute(
            select(func.max(Policy.revision)).where(
                Policy.org_id == principal.org_id, Policy.name == body.name
            )
        ).scalar_one()
        or 0
    ) + 1
    spec = body.spec.model_dump(mode="json")
    policy = Policy(
        id=uuid4(),
        org_id=principal.org_id,
        name=body.name,
        revision=revision,
        spec=spec,
        digest=_digest(spec, packs),
        state="draft",
        author_id=principal.user_id,
    )
    db.add(policy)
    db.flush()
    for pack in packs:
        db.add(
            PolicyPack(
                org_id=principal.org_id,
                policy_id=policy.id,
                rule_pack_id=pack.id,
                pack_digest=pack.digest,
            )
        )
    append_audit_event(
        db,
        principal,
        action="policy.draft_created",
        object_type="policy",
        object_id=policy.id,
        details={"revision": revision, "reason": body.reason, "digest": policy.digest},
    )
    result = _read(policy, packs)
    save_response(db, principal, "POST:/policy-drafts", idempotency_key, result)
    response.headers["ETag"] = result["etag"]
    return result


def _locked_draft(db: Session, principal: Principal, policy_id: UUID, etag: str) -> Policy:
    policy = db.execute(
        select(Policy)
        .where(Policy.org_id == principal.org_id, Policy.id == policy_id)
        .with_for_update()
    ).scalar_one_or_none()
    if policy is None:
        raise AppError(404, "NOT_FOUND", "Not found", "The requested resource is not available.")
    if policy.state != "draft":
        raise AppError(
            409,
            "POLICY_IMMUTABLE",
            "Policy is immutable",
            "Create a new draft revision to change this policy.",
        )
    if etag != f'"{policy.row_version}"':
        raise AppError(
            412,
            "STALE_VERSION",
            "Policy has changed",
            "Refresh the policy before applying your change.",
        )
    return policy


@router.patch("/policy-drafts/{policy_id}")
def update_draft(
    policy_id: UUID,
    body: PolicyDraftPatch,
    principal: PrincipalDep,
    db: DbDep,
    response: Response,
    if_match: ETag,
):
    _role(principal, {"policy_author"})
    policy = _locked_draft(db, principal, policy_id, if_match)
    _scope(principal, PolicySpec.model_validate(policy.spec), {"policy_author"})
    _scope(principal, body.spec, {"policy_author"})
    if policy.author_id != principal.user_id:
        raise AppError(
            403,
            "DRAFT_AUTHOR_REQUIRED",
            "Access denied",
            "Only the draft author may edit this revision.",
        )
    if body.spec.site_ids:
        site_count = db.execute(
            select(func.count())
            .select_from(Site)
            .where(Site.org_id == principal.org_id, Site.id.in_(body.spec.site_ids))
        ).scalar_one()
        if site_count != len(body.spec.site_ids):
            raise AppError(404, "NOT_FOUND", "Not found", "A requested site is unavailable.")
    packs = _packs(db, principal.org_id, policy.id)
    validate_spec(body.spec, packs)
    policy.spec = body.spec.model_dump(mode="json")
    policy.digest = _digest(policy.spec, packs)
    policy.row_version += 1
    append_audit_event(
        db,
        principal,
        action="policy.draft_updated",
        object_type="policy",
        object_id=policy.id,
        details={"reason": body.reason, "digest": policy.digest},
    )
    response.headers["ETag"] = f'"{policy.row_version}"'
    return _read(policy, packs)


@router.post("/policy-drafts/{policy_id}/publish", status_code=201)
def publish_draft(
    policy_id: UUID,
    body: PolicyPublish,
    principal: PrincipalDep,
    db: DbDep,
    response: Response,
    if_match: ETag,
    idempotency_key: IDKey,
):
    _role(principal, {"policy_approver"})
    require_recent_mfa(principal)
    route = f"POST:/policy-drafts/{policy_id}/publish"
    replay = claim_request(
        db, principal, route, idempotency_key, {**body.model_dump(), "etag": if_match}
    )
    if replay:
        return replay
    policy = _locked_draft(db, principal, policy_id, if_match)
    _scope(principal, PolicySpec.model_validate(policy.spec), {"policy_approver"})
    if policy.author_id == principal.user_id:
        raise AppError(
            403,
            "INDEPENDENT_APPROVAL_REQUIRED",
            "Independent approval required",
            "The policy author cannot approve their own revision.",
        )
    packs = _packs(db, principal.org_id, policy.id)
    validate_spec(PolicySpec.model_validate(policy.spec), packs)
    if policy.digest != _digest(policy.spec, packs):
        raise AppError(
            409,
            "POLICY_CONTENT_CHANGED",
            "Policy has changed",
            "Review the changed policy content before publication.",
        )
    policy.state = "published"
    policy.approver_id = principal.user_id
    policy.published_at = datetime.now(UTC)
    policy.row_version += 1
    append_audit_event(
        db,
        principal,
        action="policy.published",
        object_type="policy",
        object_id=policy.id,
        details={"reason": body.reason, "digest": policy.digest},
    )
    result = _read(policy, packs)
    save_response(db, principal, route, idempotency_key, result)
    response.headers["ETag"] = result["etag"]
    return result


# --- FR-06: Policy Draft Impact & Preview -----------------------------------


@router.get("/policy-drafts/{policy_id}/impact")
def preview_draft_impact(
    policy_id: UUID,
    principal: PrincipalDep,
    db: DbDep,
) -> dict[str, Any]:
    _role(principal, READ_ROLES)
    draft = db.execute(
        select(Policy)
        .where(
            Policy.id == policy_id,
            Policy.org_id == principal.org_id,
            Policy.state == "draft",
        )
    ).scalar_one_or_none()
    if draft is None:
        raise AppError(404, "NOT_FOUND", "Not found", "The policy draft is not available.")

    draft_spec = PolicySpec.model_validate(draft.spec)
    _scope(principal, draft_spec, READ_ROLES)
    draft_packs = _packs(db, principal.org_id, draft.id)
    validate_spec(draft_spec, draft_packs)

    # Compile all controls from draft packs
    draft_controls: dict[str, Any] = {}
    for pack in draft_packs:
        for c in pack.manifest.get("controls", []):
            draft_controls[c["id"]] = c

    # Find the current published baseline policy for this org
    _published_policy = db.execute(
        select(Policy)
        .where(
            Policy.org_id == principal.org_id,
            Policy.state == "published",
        )
        .order_by(desc(Policy.published_at))
        .limit(1)
    ).scalar_one_or_none()

    assets = db.execute(
        select(Asset)
        .where(Asset.org_id == principal.org_id, Asset.archived_at.is_(None))
    ).scalars().all()

    affected_assets: set[UUID] = set()
    flip_to_pass = 0
    flip_to_fail = 0
    control_changes: dict[str, dict[str, Any]] = {}

    for asset in assets:
        # Get latest result set
        latest_rs = db.execute(
            select(ResultSet)
            .where(ResultSet.asset_id == asset.id, ResultSet.org_id == principal.org_id)
            .order_by(desc(ResultSet.completed_at))
            .limit(1)
        ).scalar_one_or_none()

        if latest_rs is None:
            continue

        # Get existing control results
        existing_results = db.execute(
            select(ControlResultRecord)
            .where(ControlResultRecord.result_set_id == latest_rs.id)
        ).scalars().all()
        existing_by_control = {r.control_key: r.status for r in existing_results}

        # Check draft exclusions
        for excl in draft_spec.exclusions:
            if excl in existing_by_control and existing_by_control[excl] == "FAIL":
                # Excluding a failing control flips it to NOT_APPLICABLE
                affected_assets.add(asset.id)
                if excl not in control_changes:
                    control_changes[excl] = {
                        "control_id": excl,
                        "title": draft_controls.get(excl, {}).get("title", excl),
                        "prior_status": "FAIL",
                        "projected_status": "NOT_APPLICABLE",
                        "affected_asset_names": [],
                    }
                control_changes[excl]["affected_asset_names"].append(asset.name)
                flip_to_pass += 1

        # Check draft overrides
        for ctrl_id, override in draft_spec.overrides.items():
            if ctrl_id in existing_by_control:
                prior = existing_by_control[ctrl_id]
                # If threshold changed, check if it affects status
                if override.threshold is not None:
                    # Simulated projection based on threshold modification
                    affected_assets.add(asset.id)
                    if ctrl_id not in control_changes:
                        control_changes[ctrl_id] = {
                            "control_id": ctrl_id,
                            "title": draft_controls.get(ctrl_id, {}).get("title", ctrl_id),
                            "prior_status": prior,
                            "projected_status": "PASS" if prior == "FAIL" else "FAIL",
                            "affected_asset_names": [],
                        }
                    control_changes[ctrl_id]["affected_asset_names"].append(asset.name)
                    if prior == "FAIL":
                        flip_to_pass += 1
                    else:
                        flip_to_fail += 1

    return {
        "policy_id": str(draft.id),
        "total_active_assets": len(assets),
        "affected_assets_count": len(affected_assets),
        "flipping_to_pass": flip_to_pass,
        "flipping_to_fail": flip_to_fail,
        "controls_impact": list(control_changes.values()),
    }

