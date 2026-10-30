"""FR-18: Internal and distributed site collector protocol routes (PRD Section 14.4).

Distributed site collectors pull pending jobs for their authorized site,
execute read-only adapters locally, and post back immutable snapshot payloads.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Annotated, Any
from uuid import UUID, uuid4

from baselineguard_persistence.models import (
    Asset,
    Job,
    ScanRun,
    ScanTarget,
    Snapshot,
)
from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from baselineguard_api.dependencies import get_org_db
from baselineguard_api.errors import AppError
from baselineguard_api.security import Principal, require_principal

router = APIRouter(prefix="/collector", tags=["collector"])
PrincipalDep = Annotated[Principal, Depends(require_principal)]
DbDep = Annotated[Session, Depends(get_org_db)]


class JobClaimRequest(BaseModel):
    site_id: UUID
    collector_id: UUID = Field(default_factory=uuid4)
    supported_adapters: list[str] = ["linux-ssh", "windows-local", "cisco-iosxe", "fortigate-ssh"]


class JobClaimResponse(BaseModel):
    job_id: UUID | None
    lease_token: UUID | None
    target: dict[str, Any] | None


class SnapshotUploadRequest(BaseModel):
    job_id: UUID
    lease_token: UUID
    target_id: UUID
    facts: list[dict[str, Any]]
    identity: dict[str, Any] = {}
    source: str = "live"
    error_code: str | None = None
    artifacts: list[dict[str, Any]] = []


@router.post("/jobs/claim", response_model=JobClaimResponse)
def claim_collector_job(
    body: JobClaimRequest,
    principal: PrincipalDep,
    db: DbDep,
) -> JobClaimResponse:
    """Site-scoped collector worker claims a pending COLLECT job."""
    if not principal.roles.intersection({"scan_operator", "platform_admin"}):
        raise AppError(403, "FORBIDDEN", "Forbidden", "Only authorized collector agents may claim jobs.")

    now = datetime.now(UTC)
    lease_token = uuid4()

    # Claim next eligible job
    stmt = (
        select(Job, ScanTarget, Asset)
        .join(ScanTarget, Job.target_id == ScanTarget.id)
        .join(Asset, ScanTarget.asset_id == Asset.id)
        .where(
            Job.org_id == principal.org_id,
            Job.kind == "COLLECT",
            Job.state == "QUEUED",
            Asset.site_id == body.site_id,
            Asset.adapter_id.in_(body.supported_adapters),
            Job.cancel_requested_at.is_(None),
            Job.available_at <= now,
        )
        .order_by(Job.available_at, Job.id)
        .limit(1)
        .with_for_update(skip_locked=True)
    )

    row = db.execute(stmt).first()
    if row is None:
        return JobClaimResponse(job_id=None, lease_token=None, target=None)

    job, target, asset = row
    job.state = "RUNNING"
    job.lease_owner = body.collector_id
    job.lease_token = lease_token
    job.lease_expires_at = now + timedelta(minutes=5)
    job.attempt = (job.attempt or 0) + 1

    target.state = "COLLECTING"
    db.flush()

    target_data = {
        "target_id": str(target.id),
        "run_id": str(target.run_id),
        "asset_id": str(asset.id),
        "asset_name": asset.name,
        "address": asset.address,
        "port": asset.port,
        "adapter_id": asset.adapter_id,
        "declared_role": asset.declared_role,
        "policy_id": job.payload_ref.get("policy_id"),
    }

    return JobClaimResponse(
        job_id=job.id,
        lease_token=lease_token,
        target=target_data,
    )


@router.post("/snapshots", status_code=201)
def upload_collector_snapshot(
    body: SnapshotUploadRequest,
    principal: PrincipalDep,
    db: DbDep,
) -> dict[str, Any]:
    """Upload completed snapshot facts and advance pipeline to EVALUATE."""
    if not principal.roles.intersection({"scan_operator", "platform_admin"}):
        raise AppError(403, "FORBIDDEN", "Forbidden", "Only authorized collector agents may upload snapshots.")

    now = datetime.now(UTC)

    # Validate lease
    job = db.execute(
        select(Job)
        .where(
            Job.id == body.job_id,
            Job.org_id == principal.org_id,
            Job.lease_token == body.lease_token,
        )
        .with_for_update()
    ).scalar_one_or_none()

    if job is None:
        raise AppError(409, "LEASE_EXPIRED", "Lease lost", "The collector lease has expired or been cancelled.")

    target = db.get(ScanTarget, body.target_id)
    if target is None:
        raise AppError(404, "TARGET_NOT_FOUND", "Target not found", "Target ID does not exist.")

    snapshot_id = uuid4()
    envelope = {
        "schema_version": "1.0",
        "snapshot_id": str(snapshot_id),
        "asset_id": str(target.asset_id),
        "target_id": str(target.id),
        "collector_id": str(job.lease_owner or uuid4()),
        "identity": body.identity,
        "source": body.source,
        "error_code": body.error_code,
        "facts": body.facts,
    }

    db_snapshot = Snapshot(
        id=snapshot_id,
        org_id=principal.org_id,
        target_id=target.id,
        asset_id=target.asset_id,
        collector_id=job.lease_owner or uuid4(),
        source=body.source,
        normalized_envelope=envelope,
        created_at=now,
    )
    db.add(db_snapshot)

    # Transition job to COMPLETED
    job.state = "COMPLETED"
    job.lease_owner = None
    job.lease_token = None
    job.lease_expires_at = None

    # Update target and enqueue EVALUATE job
    target.state = "EVALUATING"
    target.frozen_identity = body.identity
    policy_id = str(job.payload_ref.get("policy_id") or "")

    db.add(
        Job(
            id=uuid4(),
            org_id=principal.org_id,
            target_id=target.id,
            kind="EVALUATE",
            state="QUEUED",
            attempt=0,
            max_attempts=3,
            payload_ref={
                "asset_id": str(target.asset_id),
                "policy_id": policy_id,
                "snapshot_id": str(snapshot_id),
                "source": body.source,
                "error_code": body.error_code,
            },
        )
    )

    run = db.get(ScanRun, target.run_id)
    if run is not None and run.status in {"QUEUED", "PREFLIGHT"}:
        run.status = "EVALUATING"
        run.started_at = run.started_at or now

    db.flush()
    return {"status": "accepted", "snapshot_id": str(snapshot_id)}


@router.post("/jobs/{job_id}/fail", status_code=200)
def fail_collector_job(
    job_id: UUID,
    reason: str,
    principal: PrincipalDep,
    db: DbDep,
) -> dict[str, Any]:
    """Collector records collection failure."""
    if not principal.roles.intersection({"scan_operator", "platform_admin"}):
        raise AppError(403, "FORBIDDEN", "Forbidden", "Only authorized collector agents may fail jobs.")
    job = db.execute(
        select(Job)
        .where(Job.id == job_id, Job.org_id == principal.org_id)
        .with_for_update()
    ).scalar_one_or_none()

    if job is None:
        raise AppError(404, "NOT_FOUND", "Not found", "Job not found.")

    error_code = reason[:64]
    job.state = "DEAD_LETTER"
    job.error_code = error_code
    job.lease_owner = None
    job.lease_token = None
    job.lease_expires_at = None

    if job.target_id:
        target = db.get(ScanTarget, job.target_id)
        if target:
            target.state = "FAILED"
            target.error_code = error_code
            target.finished_at = target.finished_at or datetime.now(UTC)

    db.flush()
    return {"status": "recorded"}
