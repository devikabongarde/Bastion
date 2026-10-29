from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from baselineguard_persistence.models import (
    Asset,
    Job,
    Organization,
    Policy,
    ScanRun,
    ScanTarget,
    Site,
)
from sqlalchemy import create_engine, select, text
from sqlalchemy.orm import Session

from baselineguard_api.routes.v1.scans import cancel_scan
from baselineguard_api.security import Principal
from baselineguard_scheduler.queue import claim_jobs, complete_job, lease_is_current, retry_job

pytestmark = [pytest.mark.integration]


def test_queue_reclaims_expired_lease_and_fences_stale_worker() -> None:
    database_url = os.getenv("BG_MIGRATION_DATABASE_URL")
    if not database_url:
        pytest.skip("set BG_MIGRATION_DATABASE_URL for PostgreSQL queue tests")

    org_id, site_id, asset_id = uuid4(), uuid4(), uuid4()
    policy_id, run_id, target_id, job_id = uuid4(), uuid4(), uuid4(), uuid4()
    worker_a, worker_b = uuid4(), uuid4()
    created = datetime.now(UTC)
    engine = create_engine(database_url)
    try:
        with Session(engine) as session:
            session.execute(
                text("SELECT set_config('app.org_id', :org_id, true)"), {"org_id": str(org_id)}
            )
            session.add(Organization(id=org_id, slug=f"queue-{org_id}", name="Queue test"))
            session.flush()
            session.add(
                Site(
                    id=site_id,
                    org_id=org_id,
                    name="Queue site",
                    timezone="UTC",
                    scope={"allowed_ports": [22]},
                )
            )
            session.add(
                Asset(
                    id=asset_id,
                    org_id=org_id,
                    site_id=site_id,
                    category="linux",
                    name="queue-test",
                    address="192.0.2.10",
                    port=22,
                    adapter_id="linux.ssh",
                    declared_role="server",
                )
            )
            session.add(
                Policy(
                    id=policy_id,
                    org_id=org_id,
                    name="Queue policy",
                    revision=1,
                    spec={},
                    digest="a" * 64,
                    state="draft",
                    author_id=uuid4(),
                )
            )
            session.flush()
            session.add(
                ScanRun(
                    id=run_id,
                    org_id=org_id,
                    policy_id=policy_id,
                    requester_id=uuid4(),
                    reason="queue integration test",
                    scope_manifest={"assets": [{"id": str(asset_id)}]},
                    created_at=created,
                )
            )
            session.flush()
            session.add(
                ScanTarget(
                    id=target_id,
                    org_id=org_id,
                    run_id=run_id,
                    asset_id=asset_id,
                    context_scope={"root": True},
                    frozen_identity={},
                )
            )
            session.flush()
            session.add(
                Job(
                    id=job_id,
                    org_id=org_id,
                    target_id=target_id,
                    kind="COLLECT",
                    max_attempts=3,
                    available_at=created,
                )
            )
            session.flush()

            first = claim_jobs(session, worker_id=worker_a, limit=1, lease_seconds=5, now=created)[
                0
            ]
            assert first.attempt == 1
            assert lease_is_current(
                session,
                job_id=job_id,
                worker_id=worker_a,
                lease_token=first.lease_token,
                now=created + timedelta(seconds=1),
            )
            assert (
                retry_job(
                    session,
                    job_id=job_id,
                    worker_id=worker_a,
                    lease_token=first.lease_token,
                    now=created + timedelta(seconds=1),
                )
                == "RETRY_WAIT"
            )
            assert not claim_jobs(
                session,
                worker_id=worker_b,
                limit=1,
                lease_seconds=5,
                now=created + timedelta(seconds=5),
            )
            second = claim_jobs(
                session,
                worker_id=worker_b,
                limit=1,
                lease_seconds=5,
                now=created + timedelta(seconds=6),
            )[0]
            assert second.attempt == 2
            assert second.lease_token != first.lease_token
            assert not complete_job(
                session,
                job_id=job_id,
                worker_id=worker_a,
                lease_token=first.lease_token,
                now=created + timedelta(seconds=6),
            )
            third = claim_jobs(
                session,
                worker_id=worker_a,
                limit=1,
                lease_seconds=5,
                now=created + timedelta(seconds=12),
            )[0]
            assert third.attempt == 3
            assert third.lease_token != second.lease_token
            assert not complete_job(
                session,
                job_id=job_id,
                worker_id=worker_b,
                lease_token=second.lease_token,
                now=created + timedelta(seconds=12),
            )
            assert complete_job(
                session,
                job_id=job_id,
                worker_id=worker_a,
                lease_token=third.lease_token,
                now=created + timedelta(seconds=12),
            )
            assert (
                session.execute(select(Job.state).where(Job.id == job_id)).scalar_one()
                == "COMPLETED"
            )
            cancel_worker, cancel_token = uuid4(), uuid4()
            session.add(
                Job(
                    id=uuid4(),
                    org_id=org_id,
                    target_id=target_id,
                    kind="COLLECT",
                    state="RUNNING",
                    attempt=1,
                    max_attempts=3,
                    available_at=created,
                    lease_owner=cancel_worker,
                    lease_token=cancel_token,
                    lease_expires_at=datetime.now(UTC) + timedelta(minutes=1),
                )
            )
            run = session.get(ScanRun, run_id)
            target = session.get(ScanTarget, target_id)
            assert run is not None and target is not None
            run.status = "COLLECTING"
            target.state = "COLLECTING"
            session.flush()
            principal = Principal(
                user_id=uuid4(),
                org_id=org_id,
                roles=frozenset({"scan_operator"}),
                site_ids=frozenset({site_id}),
            )
            accepted = cancel_scan(run_id, principal, session)
            assert accepted.status == "CANCELLED"
            assert (
                session.execute(
                    select(Job.state, Job.lease_token, Job.cancel_requested_at).where(
                        Job.org_id == org_id, Job.state == "CANCELLED"
                    )
                ).first()
                is not None
            )
            assert target.state == "CANCELLED"
            assert cancel_scan(run_id, principal, session).status == "CANCELLED"
            session.rollback()
    finally:
        engine.dispose()
