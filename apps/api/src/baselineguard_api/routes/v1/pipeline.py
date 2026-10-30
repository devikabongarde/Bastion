"""Results-side API: overview, findings, offline imports, exceptions and reports.

Everything here reads immutable result sets written by the evaluator, or writes
workflow metadata (assignments, exceptions) that never changes a technical
result. Offline imports are labeled `source = import` end to end.
"""

from __future__ import annotations

import json
import os
import secrets
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from pathlib import Path
from types import SimpleNamespace
from typing import Annotated, Any, Literal
from uuid import UUID, uuid4

from baselineguard_contracts.common import EvidencePointer, ResultStatus
from baselineguard_contracts.pipeline import (
    ExceptionCreate,
    FindingPatch,
    ImportBundle,
    ReportCreate,
    ReviewCreate,
)
from baselineguard_evidence.bundle import ArtifactStore, sha256_hex
from baselineguard_persistence.models import (
    Artifact,
    Asset,
    ControlResultRecord,
    ExceptionRecord,
    Finding,
    FindingEvent,
    Job,
    ManualReview,
    Organization,
    Policy,
    PolicyPack,
    Report,
    ResultSet,
    RulePack,
    ScanRun,
    ScanTarget,
    Snapshot,
    User,
)
from baselineguard_rule_engine.canonical import canonical_json
from fastapi import APIRouter, Depends, Query, Response
from sqlalchemy import and_, desc, func, select
from sqlalchemy.orm import Session

from baselineguard_api.audit import append_audit_event
from baselineguard_api.config import get_settings
from baselineguard_api.dependencies import get_org_db
from baselineguard_api.errors import AppError
from baselineguard_api.security import Principal, require_principal
from baselineguard_reporter import ReportDocument, ReportFinding, render_report
from baselineguard_reporter.pdf import render_pdf

router = APIRouter(tags=["assessment"])
PrincipalDep = Annotated[Principal, Depends(require_principal)]
DbDep = Annotated[Session, Depends(get_org_db)]

ANY_ROLE = {
    "viewer", "analyst", "scan_operator", "auditor", "platform_admin", "risk_approver",
    "manual_assessor", "inventory_editor", "policy_author", "policy_approver",
}
WORK_ROLES = {"analyst", "scan_operator", "platform_admin"}
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
FRESH_HOURS = 24
REMEDIATION_PATH = (
    Path(__file__).resolve().parents[6] / "content" / "remediation" / "linux-phase1.json"
)
PACK_PATH = Path(__file__).resolve().parents[6] / "content" / "original" / "phase1-linux.yaml"


def _need(principal: Principal, roles: set[str]) -> None:
    if not principal.roles.intersection(roles):
        raise AppError(
            403, "FORBIDDEN", "Access denied", "You do not have permission for this action."
        )


def _not_found() -> AppError:
    return AppError(404, "NOT_FOUND", "Not found", "The requested resource is not available.")


def _visible_sites(principal: Principal) -> frozenset[UUID] | None:
    return principal.sites_for(ANY_ROLE)


REMEDIATION_DIR = REMEDIATION_PATH.parent


@lru_cache(maxsize=1)
def _remediation_catalog() -> dict[str, Any]:
    """Merge every platform's remediation catalog (Linux, Windows, Cisco, FortiGate)."""
    catalog: dict[str, Any] = {}
    for path in sorted(REMEDIATION_DIR.glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        catalog.update(data.get("templates", {}))
    return catalog


def _store() -> ArtifactStore:
    settings = get_settings()
    key = Path(settings.master_key_file)
    if not key.exists():
        key.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(key, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(secrets.token_bytes(32))
    return ArtifactStore(settings.evidence_root, key)


def _num(value: Any) -> float | None:
    """Summaries store percentages as decimal strings; the API exposes numbers."""
    try:
        return None if value is None else float(value)
    except (TypeError, ValueError):
        return None


def _freshness(observed: datetime | None) -> str:
    if observed is None:
        return "never"
    age = datetime.now(UTC) - observed
    return "fresh" if age <= timedelta(hours=FRESH_HOURS) else "stale"


# --------------------------------------------------------------------------- overview


def _latest_result_sets(db: Session, principal: Principal) -> list[tuple[ResultSet, Asset]]:
    """Newest result set per asset, restricted to visible sites."""
    latest = (
        select(ResultSet.asset_id, func.max(ResultSet.completed_at).label("at"))
        .where(ResultSet.org_id == principal.org_id)
        .group_by(ResultSet.asset_id)
        .subquery()
    )
    statement = (
        select(ResultSet, Asset)
        .join(
            latest,
            and_(ResultSet.asset_id == latest.c.asset_id, ResultSet.completed_at == latest.c.at),
        )
        .join(Asset, and_(Asset.org_id == ResultSet.org_id, Asset.id == ResultSet.asset_id))
        .where(ResultSet.org_id == principal.org_id, Asset.archived_at.is_(None))
        .order_by(Asset.name)
    )
    sites = _visible_sites(principal)
    if sites is not None:
        statement = statement.where(Asset.site_id.in_(sites or {UUID(int=0)}))
    seen: set[UUID] = set()
    rows: list[tuple[ResultSet, Asset]] = []
    for result_set, asset in db.execute(statement).all():
        if asset.id in seen:
            continue
        seen.add(asset.id)
        rows.append((result_set, asset))
    return rows


@router.get("/overview")
def overview(principal: PrincipalDep, db: DbDep) -> dict[str, Any]:
    _need(principal, ANY_ROLE)
    sites = _visible_sites(principal)
    asset_stmt = select(Asset).where(Asset.org_id == principal.org_id, Asset.archived_at.is_(None))
    if sites is not None:
        asset_stmt = asset_stmt.where(Asset.site_id.in_(sites or {UUID(int=0)}))
    assets = db.execute(asset_stmt.order_by(Asset.name)).scalars().all()
    latest = {asset.id: rs for rs, asset in _latest_result_sets(db, principal)}

    totals = {"passed": 0, "failed": 0, "not_applicable": 0, "unknown": 0, "error": 0,
              "manual_required": 0}
    posture: list[dict[str, Any]] = []
    fresh = stale = never = 0
    snapshot_sources: dict[UUID, tuple[str, datetime]] = {}
    for snap in db.execute(
        select(Snapshot.id, Snapshot.source, Snapshot.observed_end).where(
            Snapshot.org_id == principal.org_id
        )
    ).all():
        snapshot_sources[snap.id] = (snap.source, snap.observed_end)
    for asset in assets:
        result_set = latest.get(asset.id)
        summary = result_set.summary if result_set else {}
        observed = None
        source = None
        if (
            result_set
            and result_set.snapshot_id is not None
            and result_set.snapshot_id in snapshot_sources
        ):
            source, observed = snapshot_sources[result_set.snapshot_id]
        freshness = _freshness(observed)
        fresh += freshness == "fresh"
        stale += freshness == "stale"
        never += freshness == "never"
        if result_set:
            for key in totals:
                totals[key] += int(summary.get(key, 0))
        posture.append(
            {
                "asset_id": str(asset.id),
                "name": asset.name,
                "category": asset.category,
                "criticality": asset.criticality,
                "role": asset.declared_role,
                "address": asset.address,
                "compliance_pct": _num(summary.get("evaluated_compliance_pct")),
                "completeness_pct": _num(summary.get("assessment_completeness_pct")),
                "passed": summary.get("passed", 0),
                "failed": summary.get("failed", 0),
                "unknown": summary.get("unknown", 0),
                "source": source,
                "observed_at": observed.isoformat() if observed else None,
                "freshness": freshness,
            }
        )
    assessable = totals["passed"] + totals["failed"]
    in_scope = sum(totals.values()) - totals["not_applicable"]
    compliance = round(totals["passed"] * 100 / assessable, 1) if assessable else None
    completeness = round(assessable * 100 / in_scope, 1) if in_scope else None

    open_rows = db.execute(
        select(Finding.severity, Finding.state, func.count())
        .join(Asset, and_(Asset.org_id == Finding.org_id, Asset.id == Finding.asset_id))
        .where(
            Finding.org_id == principal.org_id,
            *( [Asset.site_id.in_(sites or {UUID(int=0)})] if sites is not None else []),
        )
        .group_by(Finding.severity, Finding.state)
    ).all()
    severity = {key: 0 for key in SEVERITY_ORDER}
    finding_state = {"OPEN": 0, "RISK_ACCEPTED": 0, "RESOLVED": 0}
    for sev, state, count in open_rows:
        finding_state[state] = finding_state.get(state, 0) + count
        if state == "OPEN":
            severity[sev] = severity.get(sev, 0) + count

    trend_rows = db.execute(
        select(ResultSet.completed_at, ResultSet.summary, ResultSet.asset_id)
        .where(ResultSet.org_id == principal.org_id)
        .order_by(ResultSet.completed_at)
        .limit(500)
    ).all()
    per_asset: dict[UUID, dict[str, Any]] = {}
    trend: list[dict[str, Any]] = []
    for completed_at, summary, asset_id in trend_rows:
        per_asset[asset_id] = summary
        p = sum(int(s.get("passed", 0)) for s in per_asset.values())
        f = sum(int(s.get("failed", 0)) for s in per_asset.values())
        trend.append(
            {
                "at": completed_at.isoformat(),
                "compliance_pct": round(p * 100 / (p + f), 1) if p + f else None,
                "failed": f,
            }
        )
    trend = trend[-30:]

    events = db.execute(
        select(FindingEvent, Finding.title, Finding.severity, Asset.name)
        .join(Finding, and_(Finding.org_id == FindingEvent.org_id, Finding.id == FindingEvent.finding_id))
        .join(Asset, and_(Asset.org_id == Finding.org_id, Asset.id == Finding.asset_id))
        .where(FindingEvent.org_id == principal.org_id)
        .order_by(desc(FindingEvent.occurred_at))
        .limit(8)
    ).all()
    recent_runs = db.execute(
        select(ScanRun)
        .where(ScanRun.org_id == principal.org_id)
        .order_by(desc(ScanRun.created_at))
        .limit(1)
    ).scalar_one_or_none()
    return {
        "compliance_pct": compliance,
        "completeness_pct": completeness,
        "totals": totals,
        "asset_count": len(assets),
        "freshness": {"fresh": fresh, "stale": stale, "never": never},
        "open_by_severity": severity,
        "findings_by_state": finding_state,
        "posture": posture,
        "trend": trend,
        "latest_run": (
            {"id": str(recent_runs.id), "status": recent_runs.status,
             "created_at": recent_runs.created_at.isoformat()}
            if recent_runs else None
        ),
        "recent_events": [
            {
                "kind": event.kind,
                "title": title,
                "severity": sev,
                "asset": asset_name,
                "at": event.occurred_at.isoformat(),
            }
            for event, title, sev, asset_name in events
        ],
    }


# --------------------------------------------------------------------------- findings


def _finding_dict(
    finding: Finding, asset: Asset, owner_email: str | None, exception_state: str | None
) -> dict[str, Any]:
    return {
        "id": str(finding.id),
        "asset_id": str(finding.asset_id),
        "asset_name": asset.name,
        "site_id": str(asset.site_id),
        "control_key": finding.control_key,
        "control_revision": finding.control_revision,
        "title": finding.title,
        "severity": finding.severity,
        "state": finding.state,
        "first_seen_at": finding.first_seen_at.isoformat(),
        "last_seen_at": finding.last_seen_at.isoformat(),
        "owner_id": str(finding.owner_id) if finding.owner_id else None,
        "owner_email": owner_email,
        "due_at": finding.due_at.isoformat() if finding.due_at else None,
        "exception_state": exception_state,
    }


@router.get("/findings")
def list_findings(
    principal: PrincipalDep,
    db: DbDep,
    state: Annotated[Literal["OPEN", "RESOLVED", "RISK_ACCEPTED"] | None, Query()] = None,
    severity: Annotated[Literal["critical", "high", "medium", "low"] | None, Query()] = None,
    asset_id: Annotated[UUID | None, Query()] = None,
    q: Annotated[str | None, Query(max_length=100)] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 100,
) -> dict[str, Any]:
    _need(principal, ANY_ROLE)
    statement = (
        select(Finding, Asset, User.email)
        .join(Asset, and_(Asset.org_id == Finding.org_id, Asset.id == Finding.asset_id))
        .outerjoin(User, and_(User.org_id == Finding.org_id, User.id == Finding.owner_id))
        .where(Finding.org_id == principal.org_id)
    )
    sites = _visible_sites(principal)
    if sites is not None:
        statement = statement.where(Asset.site_id.in_(sites or {UUID(int=0)}))
    if state:
        statement = statement.where(Finding.state == state)
    if severity:
        statement = statement.where(Finding.severity == severity)
    if asset_id:
        statement = statement.where(Finding.asset_id == asset_id)
    if q:
        like = f"%{q.replace('%', '').replace('_', '')}%"
        statement = statement.where(
            Finding.title.ilike(like) | Finding.control_key.ilike(like) | Asset.name.ilike(like)
        )
    rows = db.execute(statement.limit(2000)).all()
    now = datetime.now(UTC)
    active = {
        (row.asset_id, row.control_key)
        for row in db.execute(
            select(ExceptionRecord.asset_id, ExceptionRecord.control_key).where(
                ExceptionRecord.org_id == principal.org_id,
                ExceptionRecord.state == "APPROVED",
                ExceptionRecord.expires_at > now,
            )
        ).all()
    }
    items = [
        _finding_dict(
            f, a, email, "APPROVED" if (f.asset_id, f.control_key) in active else None
        )
        for f, a, email in rows
    ]
    items.sort(
        key=lambda item: (
            {"OPEN": 0, "RISK_ACCEPTED": 1, "RESOLVED": 2}[item["state"]],
            SEVERITY_ORDER[item["severity"]],
            item["asset_name"],
            item["control_key"],
        )
    )
    return {"items": items[:limit], "total": len(items)}


def _load_finding(db: Session, principal: Principal, finding_id: UUID) -> tuple[Finding, Asset]:
    row = db.execute(
        select(Finding, Asset)
        .join(Asset, and_(Asset.org_id == Finding.org_id, Asset.id == Finding.asset_id))
        .where(Finding.org_id == principal.org_id, Finding.id == finding_id)
    ).first()
    if row is None:
        raise _not_found()
    sites = _visible_sites(principal)
    if sites is not None and row[1].site_id not in sites:
        raise _not_found()
    return row[0], row[1]


@router.get("/findings/{finding_id}")
def get_finding(finding_id: UUID, principal: PrincipalDep, db: DbDep) -> dict[str, Any]:
    _need(principal, ANY_ROLE)
    finding, asset = _load_finding(db, principal, finding_id)
    email = db.execute(
        select(User.email).where(User.org_id == principal.org_id, User.id == finding.owner_id)
    ).scalar_one_or_none()
    result = db.execute(
        select(ControlResultRecord).where(
            ControlResultRecord.org_id == principal.org_id,
            ControlResultRecord.id == finding.last_result_id,
        )
    ).scalar_one_or_none()
    events = db.execute(
        select(FindingEvent, User.email)
        .outerjoin(User, and_(User.org_id == FindingEvent.org_id, User.id == FindingEvent.actor_id))
        .where(FindingEvent.org_id == principal.org_id, FindingEvent.finding_id == finding.id)
        .order_by(desc(FindingEvent.occurred_at))
        .limit(100)
    ).all()
    exceptions = db.execute(
        select(ExceptionRecord)
        .where(
            ExceptionRecord.org_id == principal.org_id,
            ExceptionRecord.asset_id == finding.asset_id,
            ExceptionRecord.control_key == finding.control_key,
        )
        .order_by(desc(ExceptionRecord.created_at))
        .limit(5)
    ).scalars().all()
    detail = _finding_dict(finding, asset, email, None)
    template = ((result.trace or {}).get("remediation_template") if result else None)
    catalog = _remediation_catalog()
    detail.update(
        {
            "events": [
                {
                    "kind": event.kind,
                    "at": event.occurred_at.isoformat(),
                    "actor": actor,
                    "payload": event.payload,
                }
                for event, actor in events
            ],
            "last_result": (
                {
                    "result_id": str(result.id),
                    "status": result.status,
                    "reason_code": result.reason_code,
                    "expected": result.expected,
                    "actual": result.actual,
                    "assessment_quality": result.assessment_quality,
                    "evidence": (result.trace or {}).get("evidence_pointers", []),
                }
                if result
                else None
            ),
            "remediation": ({"template": template, **catalog[template]}
                            if template in catalog else None),
            "exceptions": [
                {
                    "id": str(item.id),
                    "state": item.state,
                    "reason": item.reason,
                    "expires_at": item.expires_at.isoformat(),
                }
                for item in exceptions
            ],
        }
    )
    return detail


@router.patch("/findings/{finding_id}")
def patch_finding(
    finding_id: UUID, body: FindingPatch, principal: PrincipalDep, db: DbDep
) -> dict[str, Any]:
    _need(principal, WORK_ROLES)
    finding, asset = _load_finding(db, principal, finding_id)
    if body.owner_id is not None:
        owner = db.execute(
            select(User.id).where(User.org_id == principal.org_id, User.id == body.owner_id)
        ).first()
        if owner is None:
            raise _not_found()
        finding.owner_id = body.owner_id
        db.add(FindingEvent(org_id=principal.org_id, finding_id=finding.id, kind="ASSIGNED",
                            actor_id=principal.user_id, payload={"owner_id": str(body.owner_id)}))
    if body.due_at is not None:
        finding.due_at = body.due_at
        db.add(FindingEvent(org_id=principal.org_id, finding_id=finding.id, kind="DUE_SET",
                            actor_id=principal.user_id, payload={"due_at": body.due_at.isoformat()}))
    if body.comment is not None:
        db.add(FindingEvent(org_id=principal.org_id, finding_id=finding.id, kind="COMMENT",
                            actor_id=principal.user_id, payload={"comment": body.comment}))
    append_audit_event(db, principal, action="finding.updated", object_type="finding",
                       object_id=finding.id, details={"fields": sorted(body.model_dump(exclude_none=True))})
    db.flush()
    return _finding_dict(finding, asset, None, None)


@router.get("/users")
def list_users(principal: PrincipalDep, db: DbDep) -> dict[str, Any]:
    _need(principal, ANY_ROLE)
    rows = db.execute(
        select(User.id, User.email).where(User.org_id == principal.org_id, User.disabled_at.is_(None))
    ).all()
    return {"items": [{"id": str(r.id), "email": r.email} for r in rows]}


# --------------------------------------------------------------------------- imports


PACK_DIR = Path(__file__).resolve().parents[6] / "content" / "original"

FAMILY_SAMPLE_CONFIG: dict[str, tuple[Path, str, dict[str, str]]] = {
    "ubuntu": (
        PACK_DIR / "phase1-linux.yaml",
        "linux-ssh-fixture",
        {"vendor": "canonical", "family": "ubuntu", "version": "22.04"},
    ),
    "windows_server": (
        PACK_DIR / "windows-server-2019.yaml",
        "windows-fixture",
        {"vendor": "microsoft", "family": "windows_server", "version": "2019"},
    ),
    "cisco_ios_xe": (
        PACK_DIR / "cisco-iosxe-hardening.yaml",
        "cisco-iosxe-fixture",
        {"vendor": "cisco", "family": "cisco_ios_xe", "version": "17.12"},
    ),
    "fortigate": (
        PACK_DIR / "fortigate-fortios.yaml",
        "fortigate-fixture",
        {"vendor": "fortinet", "family": "fortigate", "version": "7.4"},
    ),
}


def _sample_facts(
    profile: str, variant: int = 0, family: str = "ubuntu", role: str | None = None
) -> dict[str, Any]:
    from baselineguard_rule_engine.packs import load_rule_pack

    pack_path, _, _ = FAMILY_SAMPLE_CONFIG.get(family, FAMILY_SAMPLE_CONFIG["ubuntu"])
    pack = load_rule_pack(pack_path.read_bytes())
    wanted = "conforming" if profile == "hardened" else "deviation"
    facts: dict[str, Any] = {}
    for index, control in enumerate(pack["controls"]):
        choose = wanted
        if profile == "mixed":
            choose = "deviation" if (index + variant) % 3 == 0 else "conforming"
        test = next((t for t in control["tests"] if t["id"] == choose), None)
        if test is None:
            continue
        for key, value in test["facts"].items():
            facts[key] = {
                "state": value.get("state", "PRESENT"),
                "value": value.get("value"),
                "unit": value.get("unit"),
            }
    if role and "platform.role" in facts:
        # Role-scoped controls (e.g. switch-only) must see the asset's real role.
        facts["platform.role"] = {"state": "PRESENT", "value": role, "unit": None}
    return facts


@router.get("/imports/sample")
def sample_bundle(
    principal: PrincipalDep,
    profile: Annotated[Literal["hardened", "mixed", "weak"], Query()] = "mixed",
    variant: Annotated[int, Query(ge=0, le=2)] = 0,
    family: Annotated[str, Query()] = "ubuntu",
    role: Annotated[str | None, Query(pattern=r"^(router|switch)$")] = None,
) -> dict[str, Any]:
    _need(principal, ANY_ROLE)
    now = datetime.now(UTC)
    _, adapter_id, identity = FAMILY_SAMPLE_CONFIG.get(family, FAMILY_SAMPLE_CONFIG["ubuntu"])
    return {
        "adapter_id": adapter_id,
        "declared_identity": identity,
        "observed_start": (now - timedelta(seconds=30)).isoformat(),
        "observed_end": now.isoformat(),
        "capture_attested": True,
        "attested_by": "sample-generator",
        "facts": _sample_facts(profile, variant, family=family, role=role),
    }


class ImportRequest(ImportBundle):
    policy_revision_id: UUID


@router.post("/imports", status_code=202)
def import_snapshot(body: ImportRequest, principal: PrincipalDep, db: DbDep) -> dict[str, Any]:
    _need(principal, {"scan_operator", "platform_admin"})
    asset = db.execute(
        select(Asset).where(
            Asset.org_id == principal.org_id, Asset.id == body.asset_id, Asset.archived_at.is_(None)
        )
    ).scalar_one_or_none()
    sites = principal.sites_for({"scan_operator", "platform_admin"})
    if asset is None or (sites is not None and asset.site_id not in sites):
        raise _not_found()
    policy = db.execute(
        select(Policy).where(
            Policy.org_id == principal.org_id,
            Policy.id == body.policy_revision_id,
            Policy.state == "published",
        )
    ).scalar_one_or_none()
    if policy is None:
        raise _not_found()
    pack_rows = db.execute(
        select(PolicyPack, RulePack)
        .join(RulePack, (RulePack.org_id == PolicyPack.org_id) & (RulePack.id == PolicyPack.rule_pack_id))
        .where(PolicyPack.org_id == principal.org_id, PolicyPack.policy_id == policy.id)
    ).all()
    if not pack_rows or any(l.pack_digest != p.digest or p.state != "approved" for l, p in pack_rows):
        raise AppError(409, "POLICY_CONTENT_UNAVAILABLE", "Policy unavailable",
                       "A linked rule pack is missing, revoked, or has changed.")

    if any(isinstance(f.value, float) for f in body.facts.values()):
        raise AppError(422, "FLOAT_FACT", "Invalid request",
                       "Fact values must be strings, integers, booleans or lists; use strings for decimals.")
    facts_payload = json.dumps(
        [
            {"fact_id": key, "state": fact.state.value, "value": fact.value,
             "unit": fact.unit, "source": None}
            for key, fact in sorted(body.facts.items())
        ],
        sort_keys=True, default=str,
    ).encode("utf-8")
    digest = sha256_hex(facts_payload)
    store = _store()
    artifact_id = uuid4()
    meta = store.write(str(principal.org_id), str(artifact_id), facts_payload,
                       media_type="application/json", classification="normalized")
    now = datetime.now(UTC)
    existing_artifact = db.execute(
        select(Artifact.id).where(Artifact.org_id == principal.org_id,
                                  Artifact.storage_key == meta["storage_key"])
    ).scalar_one_or_none()
    if existing_artifact is None:
        db.add(Artifact(id=artifact_id, org_id=principal.org_id, storage_key=meta["storage_key"],
                        sha256=meta["sha256"], media_type=meta["media_type"],
                        size_bytes=meta["size_bytes"], classification="normalized",
                        encrypted=True, key_version=meta["key_version"]))
    else:
        artifact_id = existing_artifact
    observed_end = min(body.observed_end, now)
    observed_start = min(body.observed_start, observed_end)
    non_present = sum(1 for f in body.facts.values() if f.state.value != "PRESENT")
    snapshot = Snapshot(
        id=uuid4(), org_id=principal.org_id, asset_id=asset.id, source="import",
        identity={**body.declared_identity, "adapter_id": body.adapter_id,
                  "stable_device_id": str(asset.id)},
        configuration_plane="declared",
        observed_start=observed_start, observed_end=observed_end, received_at=now, digest=digest,
        completeness={"status": "PARTIAL" if non_present else "COMPLETE",
                      "non_present_facts": non_present},
        provenance={
            "uploader_id": str(principal.user_id),
            "capture_attested": body.capture_attested,
            "attested_by": body.attested_by,
            "raw_sha256": body.raw_sha256,
            "facts_artifact": {"id": str(artifact_id), **meta},
        },
    )
    db.add(snapshot)
    run = ScanRun(
        id=uuid4(), org_id=principal.org_id, policy_id=policy.id, requester_id=principal.user_id,
        reason=f"Offline import for {asset.name}"[:500], status="EVALUATING",
        scope_manifest={"schema_version": "1.0", "source": "import",
                        "policy_revision_id": str(policy.id), "policy_digest": policy.digest,
                        "assets": [{"id": str(asset.id), "adapter_id": asset.adapter_id}]},
        created_at=now, started_at=now,
    )
    db.add(run)
    db.flush()
    target = ScanTarget(id=uuid4(), org_id=principal.org_id, run_id=run.id, asset_id=asset.id,
                        context_scope={"root": True}, frozen_identity=snapshot.identity,
                        state="EVALUATING", started_at=now)
    db.add(target)
    db.flush()
    db.add(Job(id=uuid4(), org_id=principal.org_id, target_id=target.id, kind="EVALUATE",
               state="QUEUED", attempt=0, max_attempts=3,
               payload_ref={"asset_id": str(asset.id), "policy_id": str(policy.id),
                            "snapshot_id": str(snapshot.id), "source": "import"}))
    append_audit_event(db, principal, action="snapshot.imported", object_type="snapshot",
                       object_id=snapshot.id, details={"asset_id": str(asset.id),
                                                       "digest": digest, "scan_id": str(run.id)})
    return {"scan_id": str(run.id), "snapshot_id": str(snapshot.id), "digest": digest,
            "source": "import", "freshness": "fresh"}


# --------------------------------------------------------------------------- assessments


@router.get("/assessments")
def list_assessments(principal: PrincipalDep, db: DbDep) -> dict[str, Any]:
    _need(principal, ANY_ROLE)
    runs = db.execute(
        select(ScanRun).where(ScanRun.org_id == principal.org_id)
        .order_by(desc(ScanRun.created_at)).limit(50)
    ).scalars().all()
    items: list[dict[str, Any]] = []
    for run in runs:
        rows = db.execute(
            select(ScanTarget.state, Asset.name, ResultSet.summary, ResultSet.semantic_digest)
            .join(Asset, and_(Asset.org_id == ScanTarget.org_id, Asset.id == ScanTarget.asset_id))
            .outerjoin(ResultSet, and_(ResultSet.org_id == ScanTarget.org_id,
                                       ResultSet.target_id == ScanTarget.id))
            .where(ScanTarget.org_id == principal.org_id, ScanTarget.run_id == run.id)
        ).all()
        items.append(
            {
                "id": str(run.id),
                "status": run.status,
                "reason": run.reason,
                "created_at": run.created_at.isoformat(),
                "finished_at": run.finished_at.isoformat() if run.finished_at else None,
                "source": (run.scope_manifest or {}).get("source", "live"),
                "targets": [
                    {
                        "asset": name, "state": state,
                        "compliance_pct": _num((summary or {}).get("evaluated_compliance_pct")),
                        "failed": (summary or {}).get("failed"),
                        "digest": digest,
                    }
                    for state, name, summary, digest in rows
                ],
            }
        )
    return {"items": items}


# --------------------------------------------------------------------------- exceptions


def _exception_dict(row: ExceptionRecord, asset_name: str, requester: str,
                    approver: str | None) -> dict[str, Any]:
    now = datetime.now(UTC)
    effective = row.state
    if row.state == "APPROVED" and row.expires_at <= now:
        effective = "EXPIRED"
    return {
        "id": str(row.id), "asset_id": str(row.asset_id), "asset_name": asset_name,
        "control_key": row.control_key, "reason": row.reason,
        "compensating_controls": row.compensating_controls,
        "requested_by": str(row.requested_by), "requester_email": requester,
        "approved_by": str(row.approved_by) if row.approved_by else None,
        "approver_email": approver,
        "approved_at": row.approved_at.isoformat() if row.approved_at else None,
        "expires_at": row.expires_at.isoformat(), "state": row.state,
        "effective_state": effective,
    }


@router.get("/exceptions")
def list_exceptions(principal: PrincipalDep, db: DbDep) -> dict[str, Any]:
    _need(principal, ANY_ROLE)
    requester = User.__table__.alias("requester")
    approver = User.__table__.alias("approver")
    rows = db.execute(
        select(ExceptionRecord, Asset.name, requester.c.email, approver.c.email)
        .join(Asset, and_(Asset.org_id == ExceptionRecord.org_id, Asset.id == ExceptionRecord.asset_id))
        .join(requester, and_(requester.c.org_id == ExceptionRecord.org_id,
                              requester.c.id == ExceptionRecord.requested_by))
        .outerjoin(approver, and_(approver.c.org_id == ExceptionRecord.org_id,
                                  approver.c.id == ExceptionRecord.approved_by))
        .where(ExceptionRecord.org_id == principal.org_id)
        .order_by(desc(ExceptionRecord.created_at)).limit(200)
    ).all()
    return {"items": [_exception_dict(r, name, req, app) for r, name, req, app in rows]}


@router.post("/exceptions", status_code=201)
def create_exception(body: ExceptionCreate, principal: PrincipalDep, db: DbDep) -> dict[str, Any]:
    _need(principal, WORK_ROLES)
    asset = db.execute(
        select(Asset).where(Asset.org_id == principal.org_id, Asset.id == body.asset_id)
    ).scalar_one_or_none()
    sites = principal.sites_for(WORK_ROLES)
    if asset is None or (sites is not None and asset.site_id not in sites):
        raise _not_found()
    finding = db.execute(
        select(Finding.id).where(Finding.org_id == principal.org_id,
                                 Finding.asset_id == asset.id,
                                 Finding.control_key == body.control_key)
    ).first()
    if finding is None:
        raise AppError(422, "NO_MATCHING_FINDING", "Invalid request",
                       "An exception must reference an existing finding on this asset.")
    record = ExceptionRecord(
        id=uuid4(), org_id=principal.org_id, asset_id=asset.id, control_key=body.control_key,
        reason=body.reason, compensating_controls=body.compensating_controls,
        requested_by=principal.user_id, expires_at=body.expires_at.astimezone(UTC),
        state="REQUESTED",
    )
    db.add(record)
    append_audit_event(db, principal, action="exception.requested", object_type="exception",
                       object_id=record.id, details={"control_key": body.control_key})
    db.flush()
    return _exception_dict(record, asset.name, "you", None)


def _decide_exception(db: Session, principal: Principal, exception_id: UUID,
                      decision: Literal["APPROVED", "REJECTED", "REVOKED"]) -> dict[str, Any]:
    row = db.execute(
        select(ExceptionRecord).where(ExceptionRecord.org_id == principal.org_id,
                                      ExceptionRecord.id == exception_id)
    ).scalar_one_or_none()
    if row is None:
        raise _not_found()
    if decision in {"APPROVED", "REJECTED"}:
        _need(principal, {"risk_approver"})
        if row.requested_by == principal.user_id:
            raise AppError(403, "SELF_APPROVAL_DENIED", "Access denied",
                           "A requester cannot decide their own exception.")
        if row.state != "REQUESTED":
            raise AppError(409, "INVALID_STATE", "Conflict", "The exception was already decided.")
    else:
        _need(principal, {"risk_approver", "platform_admin"})
        if row.state != "APPROVED":
            raise AppError(409, "INVALID_STATE", "Conflict", "Only an approved exception can be revoked.")
    now = datetime.now(UTC)
    if decision == "APPROVED":
        if row.expires_at <= now:
            raise AppError(422, "EXPIRED", "Invalid request", "The requested expiry has passed.")
        row.approved_by, row.approved_at = principal.user_id, now
        findings = db.execute(
            select(Finding).where(Finding.org_id == principal.org_id, Finding.asset_id == row.asset_id,
                                  Finding.control_key == row.control_key, Finding.state == "OPEN")
        ).scalars().all()
        for finding in findings:
            finding.state = "RISK_ACCEPTED"
            db.add(FindingEvent(org_id=principal.org_id, finding_id=finding.id,
                                kind="EXCEPTION_LINKED", actor_id=principal.user_id,
                                payload={"exception_id": str(row.id)}))
    elif decision == "REVOKED":
        findings = db.execute(
            select(Finding).where(Finding.org_id == principal.org_id, Finding.asset_id == row.asset_id,
                                  Finding.control_key == row.control_key,
                                  Finding.state == "RISK_ACCEPTED")
        ).scalars().all()
        for finding in findings:
            finding.state = "OPEN"
            db.add(FindingEvent(org_id=principal.org_id, finding_id=finding.id, kind="COMMENT",
                                actor_id=principal.user_id,
                                payload={"comment": "Exception revoked; finding is actionable again."}))
    row.state = decision
    append_audit_event(db, principal, action=f"exception.{decision.lower()}",
                       object_type="exception", object_id=row.id, details={})
    asset_name = db.execute(select(Asset.name).where(Asset.org_id == principal.org_id,
                                                     Asset.id == row.asset_id)).scalar_one()
    return _exception_dict(row, asset_name, "", None)


@router.post("/exceptions/{exception_id}/approve")
def approve_exception(exception_id: UUID, principal: PrincipalDep, db: DbDep) -> dict[str, Any]:
    return _decide_exception(db, principal, exception_id, "APPROVED")


@router.post("/exceptions/{exception_id}/reject")
def reject_exception(exception_id: UUID, principal: PrincipalDep, db: DbDep) -> dict[str, Any]:
    return _decide_exception(db, principal, exception_id, "REJECTED")


@router.post("/exceptions/{exception_id}/revoke")
def revoke_exception(exception_id: UUID, principal: PrincipalDep, db: DbDep) -> dict[str, Any]:
    return _decide_exception(db, principal, exception_id, "REVOKED")


# --------------------------------------------------------------------------- reports


def _report_dict(report: Report) -> dict[str, Any]:
    return {
        "id": str(report.id), "format": report.format, "state": report.state,
        "scope_summary": report.scope_manifest, "cutoff_at": report.cutoff_at.isoformat(),
        "created_at": (report.created_at or report.cutoff_at).isoformat(),
        "artifact_id": str(report.artifact_id) if report.artifact_id else None,
        "manifest_digest": report.manifest_digest, "error_code": report.error_code,
    }


@router.get("/reports")
def list_reports(principal: PrincipalDep, db: DbDep) -> dict[str, Any]:
    _need(principal, ANY_ROLE)
    rows = db.execute(select(Report).where(Report.org_id == principal.org_id)
                      .order_by(desc(Report.created_at)).limit(50)).scalars().all()
    return {"items": [_report_dict(r) for r in rows]}


@router.post("/reports", status_code=201)
def create_report(body: ReportCreate, principal: PrincipalDep, db: DbDep) -> dict[str, Any]:
    _need(principal, {"auditor", "analyst", "platform_admin"})
    pairs = _latest_result_sets(db, principal)
    if body.asset_ids:
        wanted = set(body.asset_ids)
        pairs = [(rs, a) for rs, a in pairs if a.id in wanted]
    if not pairs:
        raise AppError(409, "NO_RESULTS", "Nothing to report",
                       "No completed assessment results are available for this scope.")
    now = datetime.now(UTC)
    policy = db.execute(select(Policy).where(Policy.org_id == principal.org_id,
                                             Policy.id == pairs[0][0].policy_id)).scalar_one()
    org = db.execute(select(Organization.slug).where(Organization.id == principal.org_id)).scalar_one_or_none()
    pack_manifests = [
        row.manifest for row in db.execute(
            select(RulePack).join(PolicyPack, and_(PolicyPack.org_id == RulePack.org_id,
                                                   PolicyPack.rule_pack_id == RulePack.id))
            .where(PolicyPack.org_id == principal.org_id, PolicyPack.policy_id == policy.id)
        ).scalars().all()
    ]
    origin: dict[str, str] = {}
    for manifest in pack_manifests:
        for control in manifest.get("controls", []):
            origin[control["id"]] = control["origin"]
    catalog = _remediation_catalog()
    findings: list[ReportFinding] = []
    counts = {"assets": len(pairs), "results": 0, "pass": 0, "fail": 0, "unknown": 0,
              "not_applicable": 0, "error": 0, "manual_required": 0}
    for result_set, asset in pairs:
        records = db.execute(
            select(ControlResultRecord).where(
                ControlResultRecord.org_id == principal.org_id,
                ControlResultRecord.result_set_id == result_set.id,
                ControlResultRecord.counts_toward_score.is_(True),
            ).order_by(ControlResultRecord.control_key)
        ).scalars().all()
        for record in records:
            counts["results"] += 1
            counts[record.status.lower()] = counts.get(record.status.lower(), 0) + 1
            if body.evidence_level == "summary" and record.status == "PASS":
                continue
            template = (record.trace or {}).get("remediation_template")
            procedure = None
            if record.status == "FAIL" and template in catalog:
                item = catalog[template]
                procedure = item["summary"] + "\n" + "\n".join(item["steps"])
            pointers: list[EvidencePointer] = []
            for raw in (record.trace or {}).get("evidence_pointers", []):
                try:
                    pointers.append(EvidencePointer.model_validate(raw))
                except ValueError:
                    continue
            findings.append(ReportFinding(
                asset_id=asset.id, asset_name=asset.name, context_key=record.context_key,
                control_key=record.control_key,
                origin=origin.get(record.control_key, "organizational"),  # type: ignore[arg-type]
                severity=record.severity,  # type: ignore[arg-type]
                status=ResultStatus(record.status), reason_code=record.reason_code,
                expected=record.expected or {}, actual=record.actual,
                evidence=tuple(pointers),
                remediation_status="ready_to_review" if procedure else "unavailable",
                remediation_procedure=procedure,
            ))
    report_id = uuid4()
    omissions: list[str] = []
    if body.evidence_level == "summary":
        omissions.append("Passing results are omitted at the summary evidence level.")
    if len({rs.policy_id for rs, _ in pairs}) > 1:
        omissions.append("Assets were last assessed under different policy revisions.")
    document = ReportDocument(
        report_id=report_id, organization_id=principal.org_id, organization_name=org or "Organization",
        requester_id=principal.user_id, created_at=now, assessment_cutoff=now, policy_id=policy.id,
        policy_name=policy.name, policy_revision=policy.revision, policy_digest=policy.digest,
        engine_digest=pairs[0][0].engine_digest,
        scope={"assets": [a.name for _, a in pairs], "evidence_level": body.evidence_level},
        completeness={k: v for k, v in counts.items()}, findings=tuple(findings),
        omissions=tuple(omissions),
    )
    if body.format == "pdf":
        content = render_pdf(document)
        artifact = SimpleNamespace(
            content=content, media_type="application/pdf",
            filename=f"baselineguard-{report_id}.pdf", byte_length=len(content),
            sha256=sha256_hex(content),
        )
    else:
        artifact = render_report(document, (body.format,))[0]  # type: ignore[arg-type]
    store = _store()
    artifact_id = uuid4()
    meta = store.write(str(principal.org_id), str(artifact_id), artifact.content,
                       media_type=artifact.media_type, classification="report")
    existing = db.execute(select(Artifact.id).where(
        Artifact.org_id == principal.org_id, Artifact.storage_key == meta["storage_key"]
    )).scalar_one_or_none()
    if existing is None:
        db.add(Artifact(id=artifact_id, org_id=principal.org_id, storage_key=meta["storage_key"],
                        sha256=meta["sha256"], media_type=artifact.media_type[:100],
                        size_bytes=meta["size_bytes"], classification="report", encrypted=True,
                        key_version=meta["key_version"]))
    else:
        artifact_id = existing
    report = Report(
        id=report_id, org_id=principal.org_id, requested_by=principal.user_id, run_id=body.run_id,
        format=body.format,
        scope_manifest={"assets": counts["assets"], "results": counts["results"],
                        "filename": artifact.filename, "sha256": artifact.sha256,
                        "bytes": artifact.byte_length, "evidence_level": body.evidence_level,
                        "policy": f"{policy.name} r{policy.revision}"},
        cutoff_at=now, state="COMPLETED", artifact_id=artifact_id,
        manifest_digest=artifact.sha256, created_at=now,
    )
    db.add(report)
    append_audit_event(db, principal, action="report.created", object_type="report",
                       object_id=report.id, details={"format": body.format, "sha256": artifact.sha256})
    db.flush()
    return _report_dict(report)


@router.get("/reports/{report_id}/download")
def download_report(report_id: UUID, principal: PrincipalDep, db: DbDep) -> Response:
    _need(principal, {"auditor", "analyst", "platform_admin", "viewer"})
    report = db.execute(select(Report).where(Report.org_id == principal.org_id,
                                             Report.id == report_id)).scalar_one_or_none()
    if report is None or report.artifact_id is None:
        raise _not_found()
    artifact = db.execute(select(Artifact).where(Artifact.org_id == principal.org_id,
                                                 Artifact.id == report.artifact_id)).scalar_one()
    content = _store().read(str(principal.org_id), str(artifact.id), artifact.storage_key,
                            require_hash=artifact.sha256)
    append_audit_event(db, principal, action="report.downloaded", object_type="report",
                       object_id=report.id, details={})
    filename = (report.scope_manifest or {}).get("filename", f"baselineguard-{report.id}.{report.format}")
    return Response(
        content=content, media_type=artifact.media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"',
                 "X-Content-Type-Options": "nosniff",
                 "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; sandbox"},
    )


# --------------------------------------------------------------------------- policies view


@router.get("/policy-overview")
def policy_overview(principal: PrincipalDep, db: DbDep) -> dict[str, Any]:
    """Controls in the published policies with their latest pass/fail tallies."""
    _need(principal, ANY_ROLE)
    catalog = _remediation_catalog()
    stats: dict[str, dict[str, int]] = {}
    for result_set, _asset in _latest_result_sets(db, principal):
        for record in db.execute(
            select(ControlResultRecord.control_key, ControlResultRecord.status).where(
                ControlResultRecord.org_id == principal.org_id,
                ControlResultRecord.result_set_id == result_set.id,
                ControlResultRecord.counts_toward_score.is_(True),
            )
        ).all():
            bucket = stats.setdefault(record.control_key, {})
            bucket[record.status] = bucket.get(record.status, 0) + 1
    packs = db.execute(select(RulePack).where(RulePack.org_id == principal.org_id)).scalars().all()
    controls: list[dict[str, Any]] = []
    for pack in packs:
        for control in pack.manifest.get("controls", []):
            controls.append(
                {
                    "key": control["id"], "title": control["title"], "severity": control["severity"],
                    "origin": control["origin"], "pack": pack.pack_key, "version": pack.version,
                    "rationale": control.get("rationale"),
                    "has_remediation": control.get("remediation_template") in catalog,
                    "results": stats.get(control["id"], {}),
                }
            )
    policies = db.execute(select(Policy).where(Policy.org_id == principal.org_id)
                          .order_by(desc(Policy.published_at))).scalars().all()
    return {
        "policies": [{"id": str(p.id), "name": p.name, "revision": p.revision, "state": p.state,
                      "digest": p.digest,
                      "published_at": p.published_at.isoformat() if p.published_at else None}
                     for p in policies],
        "controls": controls,
    }


__all__ = ["router", "canonical_json"]


# --------------------------------------------------------------------------- manual review


@router.post("/findings/{finding_id}/review", status_code=201)
def review_finding(
    finding_id: UUID, body: ReviewCreate, principal: PrincipalDep, db: DbDep
) -> dict[str, Any]:
    """Append a signed-off human assessment. It never edits the engine result or resolves a finding."""
    _need(principal, {"manual_assessor", "platform_admin"})
    finding, _asset = _load_finding(db, principal, finding_id)
    if body.expires_at.tzinfo is None or body.expires_at <= datetime.now(UTC):
        raise AppError(422, "INVALID_EXPIRY", "Invalid request", "Expiry must be a future UTC time.")
    previous = db.execute(
        select(ManualReview.id).where(ManualReview.org_id == principal.org_id,
                                      ManualReview.result_id == finding.last_result_id)
        .order_by(desc(ManualReview.created_at)).limit(1)
    ).scalar_one_or_none()
    review = ManualReview(
        id=uuid4(), org_id=principal.org_id, result_id=finding.last_result_id,
        decision=body.decision, rationale=body.rationale,
        evidence_refs=[str(e) for e in body.evidence_ids], reviewer_id=principal.user_id,
        expires_at=body.expires_at.astimezone(UTC), supersedes_id=previous,
    )
    db.add(review)
    db.add(FindingEvent(org_id=principal.org_id, finding_id=finding.id, kind="MANUAL_REVIEW",
                        actor_id=principal.user_id, result_id=finding.last_result_id,
                        payload={"decision": body.decision, "comment": body.rationale}))
    append_audit_event(db, principal, action="finding.manual_review", object_type="finding",
                       object_id=finding.id, details={"decision": body.decision})
    db.flush()
    return {"id": str(review.id), "decision": review.decision,
            "note": "Recorded as an additional assessment; the automated result is unchanged."}
