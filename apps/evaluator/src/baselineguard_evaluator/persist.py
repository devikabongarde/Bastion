"""Transactional finalization of one evaluation into immutable results and the
findings lifecycle (PRD 9.2 step 7, 11.3, FR-11).

Only a newer validating assessment resolves a technical failure: a confirmed
PASS closes the finding as `FIXED_VERIFIED`; a proven NOT_APPLICABLE closes
it explicitly as `CLOSED_NO_LONGER_APPLICABLE`; UNKNOWN/ERROR never change
the technical state; exceptions are workflow metadata, never result statuses.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from baselineguard_persistence.models import (
    ControlResultRecord,
    EvidenceRef,
    ExceptionRecord,
    Finding,
    FindingEvent,
    Policy,
    ResultEvidence,
    ResultSet,
    ScanRun,
    ScanTarget,
)
from baselineguard_rule_engine.canonical import semantic_digest
from sqlalchemy import select, update
from sqlalchemy.orm import Session

RESOLVABLE_OPEN_STATES = ("OPEN", "RISK_ACCEPTED")


def finalize(
    db: Session,
    *,
    org_id: UUID,
    asset_id: UUID,
    run_id: UUID | None,
    target_id: UUID | None,
    snapshot_id: UUID | None,
    policy: Policy,
    engine_digest: str,
    results: list[dict[str, Any]],
    summary: dict[str, Any],
    view_info: dict[str, Any],
) -> UUID:
    """Persist one immutable result set and update the findings projection."""
    now = datetime.now(UTC)
    semantic = semantic_digest(
        {
            "engine_digest": engine_digest,
            "view": view_info,
            "summary": summary,
            "results": [
                {
                    "control_key": result["control_key"],
                    "revision": result.get("control_revision", 1),
                    "status": result["status"],
                    "reason_code": result["reason_code"],
                    "severity": result["severity"],
                    "actual": result.get("actual"),
                    "expected": result.get("expected"),
                }
                for result in sorted(results, key=lambda item: item["control_key"])
            ],
        }
    )
    result_set = ResultSet(
        id=uuid4(),
        org_id=org_id,
        run_id=run_id,
        target_id=target_id,
        snapshot_id=snapshot_id,
        asset_id=asset_id,
        policy_id=policy.id,
        engine_digest=engine_digest,
        view="primary",
        semantic_digest=semantic,
        summary=summary,
        completed_at=now,
    )
    db.add(result_set)
    db.flush()

    records: list[ControlResultRecord] = []
    for result in results:
        record = ControlResultRecord(
            id=uuid4(),
            org_id=org_id,
            result_set_id=result_set.id,
            control_key=result["control_key"],
            control_revision=result.get("control_revision", 1),
            context_key=result.get("context_key", "global"),
            resource_key=result.get("resource_key", "__control__"),
            status=result["status"],
            reason_code=result["reason_code"],
            expected=result.get("expected") or {},
            actual=result.get("actual"),
            severity=result["severity"],
            assessment_quality=result["assessment_quality"],
            trace={
                "title": result.get("title"),
                "remediation_template": result.get("remediation_template"),
                "evidence_pointers": result.get("evidence") or [],
            },
            counts_toward_score=result.get("counts_toward_score", True),
            parent_result_id=None,
        )
        db.add(record)
        records.append(record)
    db.flush()

    link_result_evidence(db, org_id, snapshot_id, records)

    for record in records:
        _update_finding(db, org_id, asset_id, record, now)
        _apply_active_exception(db, org_id, asset_id, record, now)

    if target_id is not None:
        has_unknown_or_error = any(
            record.status in {"UNKNOWN", "ERROR"} for record in records
        )
        state = "PARTIAL" if has_unknown_or_error else "COMPLETED"
        db.execute(
            update(ScanTarget)
            .where(ScanTarget.id == target_id, ScanTarget.org_id == org_id)
            .values(state=state, finished_at=now)
        )
    if run_id is not None:
        _refresh_run_state(db, org_id, run_id)
    return result_set.id


def link_result_evidence(
    db: Session,
    org_id: UUID,
    snapshot_id: UUID | None,
    records: list[ControlResultRecord],
) -> int:
    """Connect control results to the snapshot's evidence references.

    A fact's pointer carries the per-reader source digest; collection stored
    the same digest inside the corresponding evidence ref pointer. Matching is
    therefore deterministic from stored digests alone.
    """
    if snapshot_id is None or not records:
        return 0
    refs = db.execute(
        select(EvidenceRef.id, EvidenceRef.pointer).where(
            EvidenceRef.org_id == org_id,
            EvidenceRef.snapshot_id == snapshot_id,
        )
    ).all()
    by_source_sha: dict[str, UUID] = {}
    for ref_id, pointer in refs:
        source_sha = (pointer or {}).get("reader_source_sha256")
        if isinstance(source_sha, str) and len(source_sha) == 64:
            by_source_sha.setdefault(source_sha, ref_id)
    linked = 0
    for record in records:
        raw_pointers: Any = record.trace.get("evidence_pointers") or []
        trace_pointers: list[dict[str, Any]] = [
            item for item in raw_pointers if isinstance(item, dict)
        ]
        seen: set[UUID] = set()
        for pointer in trace_pointers:
            ref_id = by_source_sha.get(str((pointer or {}).get("artifact_sha256", "")))
            # Several evidence facts of one control often come from the same reader
            # output; link each evidence reference once per result.
            if ref_id is None or ref_id in seen:
                continue
            seen.add(ref_id)
            db.add(
                ResultEvidence(
                    org_id=org_id,
                    result_id=record.id,
                    evidence_ref_id=ref_id,
                )
            )
            linked += 1
    return linked


def _update_finding(
    db: Session, org_id: UUID, asset_id: UUID, record: ControlResultRecord, now: datetime
) -> None:
    title_value = str((record.trace or {}).get("title") or record.control_key)
    existing = db.execute(
        select(Finding)
        .where(
            Finding.org_id == org_id,
            Finding.asset_id == asset_id,
            Finding.control_key == record.control_key,
            Finding.context_key == record.context_key,
            Finding.resource_key == record.resource_key,
        )
        .with_for_update()
    ).scalar_one_or_none()

    if record.status == "FAIL":
        if existing is None:
            finding = Finding(
                id=uuid4(),
                org_id=org_id,
                asset_id=asset_id,
                control_key=record.control_key,
                control_revision=record.control_revision,
                context_key=record.context_key,
                resource_key=record.resource_key,
                title=title_value,
                severity=record.severity,
                state="OPEN",
                first_seen_at=now,
                last_seen_at=now,
                last_result_id=record.id,
            )
            db.add(finding)
            db.flush()
            db.add(
                FindingEvent(
                    finding_id=finding.id,
                    org_id=org_id,
                    kind="OPENED",
                    result_id=record.id,
                    payload={"reason_code": record.reason_code},
                )
            )
        else:
            reopen = existing.state in {"RESOLVED", "RISK_ACCEPTED"}
            risk_accepted = _active_exception(
                db, org_id, asset_id, record.control_key, now
            )
            existing.state = "RISK_ACCEPTED" if risk_accepted else "OPEN"
            existing.first_seen_at = existing.first_seen_at if not reopen else now
            existing.last_seen_at = now
            existing.last_result_id = record.id
            existing.control_revision = record.control_revision
            existing.severity = record.severity
            existing.title = title_value
            db.add(
                FindingEvent(
                    finding_id=existing.id,
                    org_id=org_id,
                    kind="STILL_FAILING",
                    result_id=record.id,
                    payload=(
                        {"reason_code": record.reason_code, "reopened": True}
                        if reopen
                        else {"reason_code": record.reason_code}
                    ),
                )
            )
        return

    if record.status in {"PASS", "NOT_APPLICABLE"} and existing is not None:
        if existing.state in RESOLVABLE_OPEN_STATES and existing.last_result_id != record.id:
            previous_state = existing.state
            existing.state = "RESOLVED"
            existing.last_seen_at = now
            existing.last_result_id = record.id
            if previous_state == "RISK_ACCEPTED":
                db.add(
                    FindingEvent(
                        finding_id=existing.id,
                        org_id=org_id,
                        kind="FIXED_VERIFIED",
                        result_id=record.id,
                        payload={"note": "finding closed while a passed exception existed"},
                    )
                )
            elif record.status == "PASS":
                db.add(
                    FindingEvent(
                        finding_id=existing.id,
                        org_id=org_id,
                        kind="FIXED_VERIFIED",
                        result_id=record.id,
                        payload={"reason_code": record.reason_code},
                    )
                )
            else:
                db.add(
                    FindingEvent(
                        finding_id=existing.id,
                        org_id=org_id,
                        kind="CLOSED_NO_LONGER_APPLICABLE",
                        result_id=record.id,
                        payload={"reason_code": record.reason_code},
                    )
                )
    # UNKNOWN and ERROR never resolve or reopen a technical finding.


def _active_exception(
    db: Session,
    org_id: UUID,
    asset_id: UUID,
    control_key: str,
    now: datetime,
) -> bool:
    row = db.execute(
        select(ExceptionRecord.id).where(
            ExceptionRecord.org_id == org_id,
            ExceptionRecord.asset_id == asset_id,
            ExceptionRecord.control_key == control_key,
            ExceptionRecord.state == "APPROVED",
            ExceptionRecord.expires_at > now,
        )
    ).first()
    return row is not None


def _apply_active_exception(
    db: Session, org_id: UUID, asset_id: UUID, record: ControlResultRecord, now: datetime
) -> None:
    if record.status not in {"FAIL"}:
        return
    if not _active_exception(db, org_id, asset_id, record.control_key, now):
        return
    finding = db.execute(
        select(Finding).where(
            Finding.org_id == org_id,
            Finding.asset_id == asset_id,
            Finding.control_key == record.control_key,
            Finding.state == "OPEN",
        )
    ).scalar_one_or_none()
    if finding is None:
        return
    finding.state = "RISK_ACCEPTED"
    db.add(
        FindingEvent(
            finding_id=finding.id,
            org_id=org_id,
            kind="EXCEPTION_LINKED",
            result_id=record.id,
            payload={"note": "approved exception active"},
        )
    )


def _refresh_run_state(db: Session, org_id: UUID, run_id: UUID) -> None:
    states = [
        row[0]
        for row in db.execute(
            select(ScanTarget.state).where(
                ScanTarget.org_id == org_id, ScanTarget.run_id == run_id
            )
        ).all()
    ]
    if not states:
        return
    run = db.get(ScanRun, run_id)
    if run is None:
        return
    if run.status == "CANCELLED":
        return
    if all(state == "COMPLETED" for state in states):
        run.status = "COMPLETED"
    elif all(state == "FAILED" for state in states):
        run.status = "FAILED"
    elif any(
        state
        in {
            "QUEUED",
            "PREFLIGHT",
            "COLLECTING",
            "NORMALIZING",
            "EVALUATING",
            "RETRY_WAIT",
        }
        for state in states
    ):
        run.status = "EVALUATING"
    else:
        run.status = "PARTIAL"
    if run.status in {"COMPLETED", "PARTIAL", "FAILED"}:
        run.finished_at = run.finished_at or datetime.now(UTC)
