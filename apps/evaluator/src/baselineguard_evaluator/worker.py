"""Deterministic evaluation worker.

Claims EVALUATE jobs, loads the persisted normalized snapshot facts plus the
frozen policy revision and pack digests, evaluates every selected control and
finalizes everything in one database transaction through `persist.finalize`.
"""

from __future__ import annotations

import json
import logging
import time
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any
from uuid import UUID, uuid4

from baselineguard_contracts.common import NormalizedFact, ResultStatus
from baselineguard_domain.scoring import summarize
from baselineguard_evidence.bundle import ArtifactStore
from baselineguard_persistence.database import get_engine
from baselineguard_persistence.models import (
    Job,
    Policy,
    PolicyPack,
    RulePack,
    ScanTarget,
    Snapshot,
)
from baselineguard_rule_engine.canonical import semantic_digest
from baselineguard_rule_engine.evaluator import evaluate_control, evaluate_expression
from baselineguard_rule_engine.logic import Truth
from baselineguard_rule_engine.resolve import resolve_controls
from sqlalchemy import select
from sqlalchemy.orm import Session

from baselineguard_evaluator.persist import finalize

logger = logging.getLogger(__name__)


ENGINE_VERSION = "1.0.0"


class EvaluationWorker:
    def __init__(
        self,
        *,
        database_url: str,
        evidence_root: str,
        master_key_file: str,
        poll_seconds: float = 2.0,
        one_shot: bool = False,
    ):
        self.engine = get_engine(database_url)
        self.poll_seconds = poll_seconds
        self.one_shot = one_shot
        self.store = ArtifactStore(evidence_root, master_key_file)

    def run_forever(self) -> None:
        while True:
            if self.run_one():
                continue
            if self.one_shot:
                return
            time.sleep(self.poll_seconds)

    def run_one(self) -> bool:
        lease_token = uuid4()
        session = Session(self.engine)
        try:
            with session.begin():
                db: Session = session
                job = db.execute(
                    select(Job)
                    .where(
                        Job.kind == "EVALUATE",
                        Job.state == "QUEUED",
                        Job.cancel_requested_at.is_(None),
                    )
                    .order_by(Job.available_at, Job.id)
                    .limit(1)
                    .with_for_update(skip_locked=True)
                ).scalar_one_or_none()
                if job is None:
                    return False
                job.state = "RUNNING"
                job.lease_owner = uuid4()
                job.lease_token = lease_token
                job.lease_expires_at = datetime.now(UTC) + timedelta(minutes=5)
                job.attempt = (job.attempt or 0) + 1
                try:
                    with db.begin_nested():
                        self._process(db, job, lease_token)
                except Exception:  # noqa: BLE001 - job pipeline boundary
                    # Never leave a poison job QUEUED: it would be retried forever and block
                    # every other evaluation behind it.
                    logger.exception("evaluation job %s failed", job.id)
                    job.state = "DEAD_LETTER"
                    job.error_code = "EVALUATOR_UNEXPECTED"
                    target = db.get(ScanTarget, job.target_id) if job.target_id else None
                    if target is not None:
                        target.state = "FAILED"
                        target.finished_at = datetime.now(UTC)
                finally:
                    job.lease_owner = None
                    job.lease_token = None
                    job.lease_expires_at = None
            return True
        finally:
            session.close()

    # --- evaluation ------------------------------------------------------------

    def _process(self, db: Session, job: Job, lease_token: UUID) -> None:
        if job.state == "CANCELLED" or job.cancel_requested_at is not None:
            return
        asset_id = UUID(str(job.payload_ref["asset_id"]))
        policy_id = UUID(str(job.payload_ref["policy_id"]))
        snapshot_value = job.payload_ref.get("snapshot_id")
        snapshot_id = UUID(str(snapshot_value)) if snapshot_value else None
        source = str(job.payload_ref.get("source", "live"))
        error_code = job.payload_ref.get("error_code")
        collection_error = str(error_code) if error_code else None

        snapshot = (
            db.execute(
                select(Snapshot).where(
                    Snapshot.org_id == job.org_id, Snapshot.id == snapshot_id
                )
            ).scalar_one_or_none()
            if snapshot_id is not None
            else None
        )
        if snapshot is None:
            job.state = "DEAD_LETTER"
            job.error_code = "SNAPSHOT_UNRESOLVABLE"
            return
        policy = db.execute(
            select(Policy).where(Policy.org_id == job.org_id, Policy.id == policy_id)
        ).scalar_one_or_none()
        if policy is None:
            job.state = "DEAD_LETTER"
            job.error_code = "POLICY_UNRESOLVABLE"
            return
        pack_links = db.execute(
            select(PolicyPack, RulePack)
            .join(
                RulePack,
                (RulePack.org_id == PolicyPack.org_id)
                & (RulePack.id == PolicyPack.rule_pack_id),
            )
            .where(PolicyPack.org_id == job.org_id, PolicyPack.policy_id == policy.id)
        ).all()
        if not pack_links:
            job.state = "DEAD_LETTER"
            job.error_code = "PACK_CONTENT_UNAVAILABLE"
            return

        try:
            facts = load_facts(self.store, job.org_id, snapshot)
        except Exception:  # noqa: BLE001 - unreadable evidence must surface as ERROR, not hang
            logger.exception("snapshot %s evidence could not be read", snapshot.id)
            facts = {}
            collection_error = collection_error or "EVIDENCE_UNREADABLE"
        engine_digest = semantic_digest(
            {
                "engine_version": ENGINE_VERSION,
                "pack_digests": sorted(str(link.pack_digest) for link, _pack in pack_links),
                "policy_digest": policy.digest,
                "snapshot_digest": snapshot.digest,
            }
        )
        results, summary, view_info = evaluate_pack_manifests(
            [pack.manifest for _link, pack in pack_links],
            policy.spec,
            facts,
            collection_error=collection_error,
            source=source,
            declared_identity=dict(snapshot.identity or {}),
        )
        result_set_id = finalize(
            db,
            org_id=job.org_id,
            asset_id=asset_id,
            run_id=job.org_id and job.target_id and job_run_target_run_id(db, job),
            target_id=job.target_id,
            snapshot_id=snapshot.id,
            policy=policy,
            engine_digest=engine_digest,
            results=results,
            summary=summary,
            view_info=view_info,
        )
        job.payload_ref = {**job.payload_ref, "result_set_id": str(result_set_id)}
        job.state = "COMPLETED"


def job_run_target_run_id(db: Session, job: Job):
    from baselineguard_persistence.models import ScanTarget

    target = (
        db.execute(
            select(ScanTarget.run_id).where(
                ScanTarget.org_id == job.org_id, ScanTarget.id == job.target_id
            )
        ).scalar_one_or_none()
        if job.target_id is not None
        else None
    )
    return target


def load_facts(store: ArtifactStore, org_id: UUID, snapshot: Snapshot) -> dict[str, Any]:
    """Load normalized facts from a snapshot's encrypted facts artifact."""
    facts_artifact: dict[str, Any] = snapshot.provenance.get("facts_artifact") or {}
    if not facts_artifact:
        return {}
    blob = store.read(str(org_id), str(facts_artifact["id"]), facts_artifact["storage_key"])
    payload = json.loads(blob)
    facts: dict[str, Any] = {}
    for item in payload:
        try:
            normalized = NormalizedFact.model_validate(item)
        except Exception:  # noqa: BLE001 - a corrupted fact is reported, not defaulted
            logger.warning(
                "snapshot %s: dropping malformed fact entry", snapshot.id, exc_info=True
            )
            continue
        facts[normalized.fact_id] = normalized
    return facts


def evaluate_pack_manifests(
    manifests: list[dict[str, Any]],
    spec: dict[str, Any],
    facts: dict[str, Any],
    *,
    collection_error: str | None,
    source: str,
    declared_identity: dict[str, Any] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any], dict[str, Any]]:
    """Evaluate every pack against the snapshot and compute score summary."""
    # When collection failed there are no facts, but the asset's declared identity still
    # tells us which controls apply: other platforms' controls are NOT_APPLICABLE and only
    # the asset's own controls are ERROR.
    identity_facts: dict[str, Any] = {}
    if collection_error and declared_identity:
        for key, field in (("platform.family", "family"), ("platform.role", "role")):
            if declared_identity.get(field):
                identity_facts[key] = NormalizedFact(
                    fact_id=key, state="PRESENT", value=declared_identity[field]
                )
    controls: list[dict[str, Any]] = []
    view_info: dict[str, Any] = {
        "excluded_count": 0,
        "accounted_recommendations": 0,
        "full_inventory": [],
        "parameters": {},
        "source": source,
    }
    for manifest in manifests:
        resolved = resolve_controls(manifest, spec)
        controls.extend(resolved["controls"])
        view_info["excluded_count"] += resolved["excluded_count"]
        view_info["accounted_recommendations"] += resolved["accounted_recommendations"]
        if resolved["full_inventory"]:
            view_info["full_inventory"].extend(resolved["full_inventory"])
        if resolved["parameters"]:
            view_info["parameters"].update(resolved["parameters"])

    results: list[dict[str, Any]] = []
    for control in controls:
        if identity_facts and evaluate_expression(control["applicability"], identity_facts) is Truth.FALSE:
            evaluated = evaluate_control(control, identity_facts)
        else:
            evaluated = evaluate_control(
                control,
                facts,
                collection_error=collection_error is not None,
            )
        evaluated["control_revision"] = int(control.get("revision", 1))
        evaluated["context_key"] = "global"
        evaluated["resource_key"] = "__control__"
        evaluated["counts_toward_score"] = True
        evaluated["parent_result_id"] = None
        evaluated["expected"] = dict(control.get("expected") or {})
        evaluated["remediation_template"] = control.get("remediation_template")
        evaluated["title"] = control.get("title")
        raw_evidence: Any = control.get("evidence") or control.get("required_facts") or []
        evidence_keys: list[str] = [str(key) for key in raw_evidence]
        # Evidence pointers are pydantic models; store them as plain JSON objects.
        evaluated["evidence"] = [
            fact.source.model_dump(mode="json")
            for fact in (facts.get(key) for key in evidence_keys)
            if fact is not None and fact.source is not None
        ]
        results.append(evaluated)

    counts: dict[str, int] = {}
    for result in results:
        counts[result["status"]] = counts.get(result["status"], 0) + 1
    known_statuses = {status.value for status in ResultStatus}
    score = summarize(
        [
            ResultStatus(result["status"])
            for result in results
            if result["status"] in known_statuses
        ]
    )
    asdict: dict[str, Any] = {
        key: (str(value) if isinstance(value, Decimal) else value)
        for key, value in dataclasses_asdict(score).items()
    }
    summary_payload: dict[str, Any] = {
        **asdict,
        "counts": counts,
        "excluded_count": view_info["excluded_count"],
    }
    return results, summary_payload, view_info


def dataclasses_asdict(value: Any) -> dict[str, Any]:
    from dataclasses import asdict

    return asdict(value)
