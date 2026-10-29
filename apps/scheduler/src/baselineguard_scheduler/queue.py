"""PostgreSQL-backed, fenced job leases for at-least-once workers.

Workers must pass the lease token to every state transition. A stale worker can
never complete a job after its lease has expired or has been replaced.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from baselineguard_persistence.models import Job
from sqlalchemy import or_, select
from sqlalchemy.orm import Session


@dataclass(frozen=True, slots=True)
class JobLease:
    job_id: UUID
    org_id: UUID
    target_id: UUID
    kind: str
    attempt: int
    lease_owner: UUID
    lease_token: UUID
    lease_expires_at: datetime
    payload_ref: dict[str, object]


def claim_jobs(
    session: Session,
    *,
    worker_id: UUID,
    limit: int = 1,
    lease_seconds: int = 60,
    now: datetime | None = None,
) -> list[JobLease]:
    """Claim ready or expired jobs atomically; requires a transaction/session scope."""
    if not 1 <= limit <= 100 or not 5 <= lease_seconds <= 900:
        raise ValueError("Queue claim bounds are outside their allowed range")
    current = now or datetime.now(UTC)
    if current.tzinfo is None:
        raise ValueError("Queue timestamps must be timezone-aware")
    statement = (
        select(Job)
        .where(
            Job.cancel_requested_at.is_(None),
            or_(
                ((Job.state.in_(("QUEUED", "RETRY_WAIT"))) & (Job.available_at <= current)),
                ((Job.state == "RUNNING") & (Job.lease_expires_at <= current)),
            ),
        )
        .order_by(Job.available_at, Job.id)
        .limit(limit)
        .with_for_update(skip_locked=True)
    )
    leases: list[JobLease] = []
    for job in session.execute(statement).scalars():
        if job.attempt >= job.max_attempts:
            job.state = "DEAD_LETTER"
            job.lease_owner = None
            job.lease_token = None
            job.lease_expires_at = None
            continue
        token = uuid4()
        expires = current + timedelta(seconds=lease_seconds)
        job.state = "RUNNING"
        job.attempt += 1
        job.lease_owner = worker_id
        job.lease_token = token
        job.lease_expires_at = expires
        leases.append(
            JobLease(
                job_id=job.id,
                org_id=job.org_id,
                target_id=job.target_id,
                kind=job.kind,
                attempt=job.attempt,
                lease_owner=worker_id,
                lease_token=token,
                lease_expires_at=expires,
                payload_ref=dict(job.payload_ref),
            )
        )
    session.flush()
    return leases


def lease_is_current(
    session: Session,
    *,
    job_id: UUID,
    worker_id: UUID,
    lease_token: UUID,
    now: datetime | None = None,
) -> bool:
    """Check fencing and cooperative cancellation immediately before side effects."""
    current = now or datetime.now(UTC)
    return (
        session.execute(
            select(Job.id).where(
                Job.id == job_id,
                Job.state == "RUNNING",
                Job.lease_owner == worker_id,
                Job.lease_token == lease_token,
                Job.lease_expires_at > current,
                Job.cancel_requested_at.is_(None),
            )
        ).scalar_one_or_none()
        is not None
    )


def complete_job(
    session: Session,
    *,
    job_id: UUID,
    worker_id: UUID,
    lease_token: UUID,
    now: datetime | None = None,
) -> bool:
    """Complete only under the live lease; return false for stale/cancelled workers."""
    job = session.execute(
        select(Job).where(Job.id == job_id).with_for_update()
    ).scalar_one_or_none()
    current = now or datetime.now(UTC)
    if (
        job is None
        or job.state != "RUNNING"
        or job.lease_owner != worker_id
        or job.lease_token != lease_token
        or job.lease_expires_at is None
        or job.lease_expires_at <= current
        or job.cancel_requested_at is not None
    ):
        return False
    job.state = "COMPLETED"
    job.lease_owner = None
    job.lease_token = None
    job.lease_expires_at = None
    session.flush()
    return True


def renew_lease(
    session: Session,
    *,
    job_id: UUID,
    worker_id: UUID,
    lease_token: UUID,
    lease_seconds: int = 60,
    now: datetime | None = None,
) -> datetime | None:
    """Extend a live lease; a cancelled, expired, or superseded lease cannot renew."""
    if not 5 <= lease_seconds <= 900:
        raise ValueError("Queue lease duration is outside its allowed range")
    current = now or datetime.now(UTC)
    job = session.execute(
        select(Job).where(Job.id == job_id).with_for_update()
    ).scalar_one_or_none()
    if (
        job is None
        or job.state != "RUNNING"
        or job.lease_owner != worker_id
        or job.lease_token != lease_token
        or job.lease_expires_at is None
        or job.lease_expires_at <= current
        or job.cancel_requested_at is not None
    ):
        return None
    job.lease_expires_at = current + timedelta(seconds=lease_seconds)
    session.flush()
    return job.lease_expires_at


def retry_job(
    session: Session,
    *,
    job_id: UUID,
    worker_id: UUID,
    lease_token: UUID,
    now: datetime | None = None,
    base_delay_seconds: int = 5,
    max_delay_seconds: int = 300,
) -> str | None:
    """Schedule bounded exponential retry, or dead-letter on exhaustion.

    Returns the resulting state, or None when the caller's lease is stale.
    """
    if not 1 <= base_delay_seconds <= 300 or not base_delay_seconds <= max_delay_seconds <= 3600:
        raise ValueError("Queue retry delay bounds are invalid")
    current = now or datetime.now(UTC)
    job = session.execute(
        select(Job).where(Job.id == job_id).with_for_update()
    ).scalar_one_or_none()
    if (
        job is None
        or job.state != "RUNNING"
        or job.lease_owner != worker_id
        or job.lease_token != lease_token
        or job.lease_expires_at is None
        or job.lease_expires_at <= current
        or job.cancel_requested_at is not None
    ):
        return None
    if job.attempt >= job.max_attempts:
        job.state = "DEAD_LETTER"
    else:
        job.state = "RETRY_WAIT"
        delay = min(max_delay_seconds, base_delay_seconds * (2 ** (job.attempt - 1)))
        job.available_at = current + timedelta(seconds=delay)
    job.lease_owner = None
    job.lease_token = None
    job.lease_expires_at = None
    session.flush()
    return job.state
