"""Schedule tick: turn due cron occurrences into scan runs, once per occurrence."""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from uuid import uuid4

from baselineguard_persistence.models import (
    Asset,
    Job,
    ScanRun,
    ScanTarget,
    Schedule,
    ScheduleOccurrence,
)
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from baselineguard_scheduler.schedule import next_occurrence

logger = logging.getLogger(__name__)


def run_due_schedules(db: Session, now: datetime | None = None) -> int:
    """Enqueue every due, not-yet-recorded occurrence. Returns runs created.

    Fixture/offline adapters are skipped: only live adapters can be collected on a schedule.
    """
    now = now or datetime.now(UTC)
    created = 0
    for schedule in db.execute(select(Schedule).where(Schedule.enabled.is_(True))).scalars():
        last = db.execute(
            select(ScheduleOccurrence.occurrence_at)
            .where(
                ScheduleOccurrence.org_id == schedule.org_id,
                ScheduleOccurrence.schedule_id == schedule.id,
            )
            .order_by(ScheduleOccurrence.occurrence_at.desc())
            .limit(1)
        ).scalar_one_or_none()
        try:
            due = next_occurrence(
                schedule.cron, after=last or schedule.created_at, timezone=schedule.timezone
            )
        except ValueError:
            logger.warning("schedule %s has an invalid expression", schedule.id)
            continue
        if due > now:
            continue
        # The primary key (org, schedule, occurrence) makes repeated ticks idempotent.
        inserted = db.execute(
            insert(ScheduleOccurrence)
            .values(
                org_id=schedule.org_id,
                schedule_id=schedule.id,
                occurrence_at=due,
                status="ENQUEUED",
            )
            .on_conflict_do_nothing()
            .returning(ScheduleOccurrence.schedule_id)
        ).scalar_one_or_none()
        if inserted is None:
            continue
        occurrence = db.get(ScheduleOccurrence, (schedule.org_id, schedule.id, due))
        assets = (
            db.execute(
                select(Asset).where(
                    Asset.org_id == schedule.org_id,
                    Asset.site_id == schedule.site_id,
                    Asset.archived_at.is_(None),
                )
            )
            .scalars()
            .all()
        )
        eligible = [a for a in assets if not a.adapter_id.endswith("fixture")]
        if not eligible or occurrence is None:
            if occurrence is not None:
                occurrence.status = "SKIPPED"
            continue
        run = ScanRun(
            id=uuid4(),
            org_id=schedule.org_id,
            policy_id=schedule.policy_id,
            requester_id=schedule.created_by,
            status="QUEUED",
            reason=f"Scheduled: {schedule.name}"[:500],
            created_at=now,
            scope_manifest={
                "schema_version": "1.0",
                "source": "live",
                "schedule_id": str(schedule.id),
                "assets": [{"id": str(a.id)} for a in eligible],
            },
        )
        db.add(run)
        db.flush()
        for asset in eligible:
            target = ScanTarget(
                id=uuid4(),
                org_id=schedule.org_id,
                run_id=run.id,
                asset_id=asset.id,
                context_scope={"root": True},
                frozen_identity=asset.identity or {},
                state="QUEUED",
            )
            db.add(target)
            db.flush()
            db.add(
                Job(
                    id=uuid4(),
                    org_id=schedule.org_id,
                    target_id=target.id,
                    kind="COLLECT",
                    state="QUEUED",
                    attempt=0,
                    max_attempts=3,
                    payload_ref={
                        "asset_id": str(asset.id),
                        "adapter_id": asset.adapter_id,
                        "policy_id": str(schedule.policy_id),
                    },
                )
            )
        occurrence.run_id = run.id
        created += 1
    return created
