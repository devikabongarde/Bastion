"""Schedules and drift comparison."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Any
from uuid import UUID, uuid4

from baselineguard_contracts.pipeline import ScheduleCreate
from baselineguard_persistence.models import (
    Asset,
    ControlResultRecord,
    Policy,
    ResultSet,
    Schedule,
    ScheduleOccurrence,
    Site,
)
from fastapi import APIRouter, Depends
from sqlalchemy import and_, desc, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from baselineguard_api.audit import append_audit_event
from baselineguard_api.dependencies import get_org_db
from baselineguard_api.errors import AppError
from baselineguard_api.routes.v1.pipeline import ANY_ROLE, _need, _not_found, _visible_sites
from baselineguard_api.security import Principal, require_principal
from baselineguard_scheduler.schedule import next_occurrence

router = APIRouter(tags=["schedules"])
PrincipalDep = Annotated[Principal, Depends(require_principal)]
DbDep = Annotated[Session, Depends(get_org_db)]
OPERATORS = {"scan_operator", "platform_admin"}


def _dict(row: Schedule, site_name: str, last: datetime | None) -> dict[str, Any]:
    try:
        upcoming = next_occurrence(row.cron, after=last or datetime.now(UTC), timezone=row.timezone)
    except ValueError:
        upcoming = None
    return {
        "id": str(row.id),
        "name": row.name,
        "site_id": str(row.site_id),
        "site_name": site_name,
        "policy_id": str(row.policy_id),
        "cron": row.cron,
        "timezone": row.timezone,
        "overlap_policy": row.overlap_policy,
        "enabled": row.enabled,
        "last_occurrence_at": last.isoformat() if last else None,
        "next_occurrence_at": upcoming.isoformat() if upcoming and row.enabled else None,
    }


@router.get("/schedules")
def list_schedules(principal: PrincipalDep, db: DbDep) -> dict[str, Any]:
    _need(principal, ANY_ROLE)
    items = []
    rows = db.execute(
        select(Schedule, Site.name)
        .join(Site, and_(Site.org_id == Schedule.org_id, Site.id == Schedule.site_id))
        .where(Schedule.org_id == principal.org_id)
        .order_by(Schedule.name)
    ).all()
    for row, site_name in rows:
        last = db.execute(
            select(func.max(ScheduleOccurrence.occurrence_at)).where(
                ScheduleOccurrence.org_id == principal.org_id,
                ScheduleOccurrence.schedule_id == row.id,
            )
        ).scalar_one_or_none()
        items.append(_dict(row, site_name, last))
    sites = db.execute(select(Site.id, Site.name).where(Site.org_id == principal.org_id)).all()
    return {"items": items, "sites": [{"id": str(i), "name": n} for i, n in sites]}


@router.post("/schedules", status_code=201)
def create_schedule(body: ScheduleCreate, principal: PrincipalDep, db: DbDep) -> dict[str, Any]:
    _need(principal, OPERATORS)
    try:
        next_occurrence(body.cron, after=datetime.now(UTC), timezone=body.timezone)
    except ValueError as exc:
        raise AppError(422, "INVALID_SCHEDULE", "Invalid schedule", str(exc)) from None
    site = db.execute(
        select(Site).where(Site.org_id == principal.org_id, Site.id == body.site_id)
    ).scalar_one_or_none()
    policy = db.execute(
        select(Policy.id).where(
            Policy.org_id == principal.org_id,
            Policy.id == body.policy_id,
            Policy.state == "published",
        )
    ).first()
    if site is None or policy is None:
        raise _not_found()
    row = Schedule(
        id=uuid4(),
        org_id=principal.org_id,
        site_id=site.id,
        policy_id=body.policy_id,
        name=body.name,
        cron=body.cron,
        timezone=body.timezone,
        overlap_policy=body.overlap_policy,
        enabled=True,
        created_by=principal.user_id,
    )
    db.add(row)
    try:
        db.flush()
    except IntegrityError:
        raise AppError(409, "SCHEDULE_EXISTS", "Conflict", "That schedule name exists.") from None
    append_audit_event(
        db, principal, action="schedule.created", object_type="schedule",
        object_id=row.id, details={"cron": body.cron},
    )
    return _dict(row, site.name, None)


@router.post("/schedules/{schedule_id}/toggle")
def toggle_schedule(schedule_id: UUID, principal: PrincipalDep, db: DbDep) -> dict[str, Any]:
    _need(principal, OPERATORS)
    row = db.execute(
        select(Schedule).where(Schedule.org_id == principal.org_id, Schedule.id == schedule_id)
    ).scalar_one_or_none()
    if row is None:
        raise _not_found()
    row.enabled = not row.enabled
    append_audit_event(
        db, principal, action="schedule.toggled", object_type="schedule",
        object_id=row.id, details={"enabled": row.enabled},
    )
    name = db.execute(
        select(Site.name).where(Site.org_id == principal.org_id, Site.id == row.site_id)
    ).scalar_one()
    return _dict(row, name, None)


@router.get("/assets/{asset_id}/drift")
def asset_drift(asset_id: UUID, principal: PrincipalDep, db: DbDep) -> dict[str, Any]:
    """Compare the two newest result sets of an asset (FR-16)."""
    _need(principal, ANY_ROLE)
    asset = db.execute(
        select(Asset).where(Asset.org_id == principal.org_id, Asset.id == asset_id)
    ).scalar_one_or_none()
    sites = _visible_sites(principal)
    if asset is None or (sites is not None and asset.site_id not in sites):
        raise _not_found()
    sets = (
        db.execute(
            select(ResultSet)
            .where(ResultSet.org_id == principal.org_id, ResultSet.asset_id == asset_id)
            .order_by(desc(ResultSet.completed_at))
            .limit(2)
        )
        .scalars()
        .all()
    )
    if len(sets) < 2:
        return {"comparable": False, "reason": "At least two assessments are required.",
                "changes": []}
    newer, older = sets
    status: dict[str, dict[str, str]] = {}
    for key, result_set in (("new", newer), ("old", older)):
        status[key] = {
            r.control_key: r.status
            for r in db.execute(
                select(ControlResultRecord.control_key, ControlResultRecord.status).where(
                    ControlResultRecord.org_id == principal.org_id,
                    ControlResultRecord.result_set_id == result_set.id,
                )
            ).all()
        }
    changes: list[dict[str, str | None]] = [
        {"control_key": k, "from": status["old"].get(k), "to": v}
        for k, v in sorted(status["new"].items())
        if status["old"].get(k) != v
    ]
    same = newer.policy_id == older.policy_id
    return {
        "comparable": same,
        "reason": None if same else "Policies differ; changes reflect policy, not only drift.",
        "from_at": older.completed_at.isoformat(),
        "to_at": newer.completed_at.isoformat(),
        "changes": changes,
    }
