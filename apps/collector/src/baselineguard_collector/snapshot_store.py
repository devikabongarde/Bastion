"""Persist a normalized collection as an immutable snapshot with artifacts.

The collector redacts before persistence (PRD 16.3): raw reader output is
stored only in encrypted, content-addressed artifacts and each fact carries
its own redacted evidence pointer.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from baselineguard_adapters.linux.ssh import ReadOutput
from baselineguard_adapters.orchestrate import normalize_outputs
from baselineguard_contracts.common import CollectionEnvelope, FactState, NormalizedFact
from baselineguard_evidence.bundle import ArtifactStore, sha256_hex
from baselineguard_persistence.models import Artifact, EvidenceRef, Snapshot
from sqlalchemy.orm import Session


class CollectionOutcome:
    """Typed outcome of one target collection attempt."""

    def __init__(
        self,
        *,
        adapter_id: str,
        reader_outputs: tuple[ReadOutput, ...],
        error_code: str | None,
        source: str = "live",
        observed_start: datetime,
        observed_end: datetime,
        identity: dict[str, Any],
    ):
        self.adapter_id = adapter_id
        self.reader_outputs = reader_outputs
        self.error_code = error_code
        self.source = source
        self.observed_start = observed_start
        self.observed_end = observed_end
        self.identity = identity


def read_outputs_from_fixture(
    fixture: dict[str, str], adapter_id: str
) -> tuple[ReadOutput, ...]:
    """Build trusted ReadOutputs from a declared fixture mapping reader_id->text.

    Fixture bundles are labeled sources only; the caller records
    `source='fixture'` so snapshots cannot masquerade as live evidence.
    """
    outputs: list[ReadOutput] = []
    if adapter_id.startswith("linux"):
        valid = {
            "linux.identity.uname", "linux.identity.os_release",
            "linux.ssh.effective_config", "linux.kernel.security_sysctl",
            "linux.files.security_modes", "linux.auth.umask_defaults",
            "linux.auditd.active", "linux.time.ntp_state",
        }
    elif adapter_id.startswith("cisco-iosxe"):
        valid = {
            "iosxe.identity.show_version",
            "iosxe.config.running",
            "iosxe.time.clock",
            "iosxe.switch.interfaces_switchport",
            "iosxe.switch.spanning_tree",
            "iosxe.switch.port_security",
            "iosxe.switch.vlans_brief",
        }
    elif adapter_id.startswith("windows"):
        valid = {
            "windows.identity.os_version",
            "windows.registry.security_settings",
            "windows.security_policy.secedit",
            "windows.audit.auditpol",
            "windows.firewall.profiles",
            "windows.services.state",
        }
    elif adapter_id.startswith("fortigate"):
        valid = {
            "fortigate.identity.status",
            "fortigate.system.global",
            "fortigate.admin.settings",
            "fortigate.firewall.policy",
            "fortigate.system.interface",
            "fortigate.log.syslog",
        }
    else:
        raise ValueError(f"unsupported fixture adapter: {adapter_id}")
    for reader_id, text in fixture.items():
        if reader_id not in valid:
            raise ValueError(f"fixture declares an unapproved reader: {reader_id}")
        payload = text.encode("utf-8")
        outputs.append(
            ReadOutput(
                reader_id=reader_id,
                text=text,
                exit_code=0,
                output_bytes=len(payload),
                source_sha256=hashlib.sha256(payload).hexdigest(),
            )
        )
    return tuple(outputs)


def persist_snapshot(
    db: Session,
    store: ArtifactStore,
    outcome: CollectionOutcome,
    *,
    org_id: UUID,
    asset_id: UUID,
    target_id: UUID | None,
    collector_id: UUID,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Write snapshot + artifact + evidence references and return (snapshot, envelope)."""
    facts = normalize_outputs(
        [(output.reader_id, output) for output in outcome.reader_outputs]
    )

    raw_payload = json.dumps(
        {
            "reader_outputs": [
                {
                    "reader_id": output.reader_id,
                    "text": output.text,
                    "exit_code": output.exit_code,
                    "source_sha256": output.source_sha256,
                }
                for output in outcome.reader_outputs
            ]
        },
        sort_keys=True,
    ).encode("utf-8")
    raw_artifact_id = uuid4()
    raw_meta = store.write(
        str(org_id),
        str(raw_artifact_id),
        raw_payload,
        media_type="application/json",
        classification="redacted",
    )

    identity = dict(outcome.identity)
    identity.setdefault("adapter_id", outcome.adapter_id)
    facts_json = json.dumps(
        [
            {
                "fact_id": f.fact_id,
                "state": f.state.value,
                "value": f.value,
                "source": f.source,
            }
            for f in facts
        ],
        sort_keys=True,
        default=str,
    ).encode("utf-8")
    facts_artifact_id = uuid4()
    facts_meta = store.write(
        str(org_id),
        str(facts_artifact_id),
        facts_json,
        media_type="application/json",
        classification="normalized",
    )

    snapshot_digest = sha256_hex(facts_json)
    now = datetime.now(UTC)
    snapshot = Snapshot(
        id=uuid4(),
        org_id=org_id,
        target_id=target_id,
        asset_id=asset_id,
        source=outcome.source,
        identity=identity,
        configuration_plane="effective",
        observed_start=outcome.observed_start,
        observed_end=outcome.observed_end,
        received_at=now,
        digest=snapshot_digest,
        completeness=_completeness(outcome, facts),
        provenance={
            "collector_id": str(collector_id),
            "adapter_id": outcome.adapter_id,
            "error_code": outcome.error_code,
            "raw_artifact": {"id": str(raw_artifact_id), **raw_meta},
            "facts_artifact": {"id": str(facts_artifact_id), **facts_meta},
        },
    )
    db.add(snapshot)
    db.flush()
    db.add(
        Artifact(
            id=raw_artifact_id,
            org_id=org_id,
            storage_key=raw_meta["storage_key"],
            sha256=raw_meta["sha256"],
            media_type=raw_meta["media_type"],
            size_bytes=raw_meta["size_bytes"],
            classification="redacted",
            encrypted=True,
            key_version=raw_meta["key_version"],
        )
    )
    db.add(
        Artifact(
            id=facts_artifact_id,
            org_id=org_id,
            storage_key=facts_meta["storage_key"],
            sha256=facts_meta["sha256"],
            media_type=facts_meta["media_type"],
            size_bytes=facts_meta["size_bytes"],
            classification="normalized",
            encrypted=True,
            key_version=facts_meta["key_version"],
        )
    )
    for output in outcome.reader_outputs:
        db.add(
            EvidenceRef(
                id=uuid4(),
                org_id=org_id,
                snapshot_id=snapshot.id,
                artifact_id=raw_artifact_id,
                reader_id=output.reader_id,
                pointer={
                    "lines": [1, max(1, output.text.count("\n") + 1)],
                    "reader_source_sha256": output.source_sha256,
                },
                redaction_version="v1",
            )
        )
    envelope_payload = CollectionEnvelope.model_validate(
        {
            "schema_version": "1.0",
            "asset_id": asset_id,
            "collector_id": collector_id,
            "adapter_id": outcome.adapter_id,
            "adapter_version": "1.0.0",
            "identity": {
                "vendor": identity.get("vendor", "unknown"),
                "family": identity.get("family", "unknown"),
                "version": identity.get("version", "unknown"),
                "role": identity.get("role", "unknown"),
                "stable_device_id": identity.get("stable_device_id", str(asset_id)),
            },
            "observed_start": outcome.observed_start,
            "observed_end": outcome.observed_end,
            "received_at": now,
            "configuration_plane": "effective",
            "readers": [
                {
                    "reader_id": output.reader_id,
                    "state": "COMPLETED",
                    "duration_ms": 0,
                    "output_bytes": output.output_bytes,
                }
                for output in outcome.reader_outputs
            ],
            "facts": [
                {
                    "fact_id": f.fact_id,
                    "state": f.state.value,
                    "value": f.value,
                    "unit": f.unit,
                    "source": f.source,
                }
                for f in facts
            ],
            "artifact_sha256": snapshot_digest,
            "completeness": _completeness(outcome, facts),
        }
    ).model_dump(mode="json")
    return {"snapshot_id": str(snapshot.id), "digest": snapshot_digest}, envelope_payload


def _completeness(outcome: CollectionOutcome, facts: list[Any]) -> dict[str, Any]:
    if outcome.error_code:
        return {"status": "INCOMPLETE", "error_code": outcome.error_code}
    unavailable = [f.fact_id for f in facts if f.state is not FactState.PRESENT]
    if unavailable:
        return {
            "status": "PARTIAL",
            "non_present_facts": len(unavailable),
        }
    return {"status": "COMPLETE"}


def load_snapshot_facts(
    store: ArtifactStore, org_id: UUID, snapshot: Snapshot
) -> list[NormalizedFact]:
    """Load normalized facts from the snapshot's encrypted facts artifact."""
    facts_artifact = snapshot.provenance.get("facts_artifact")
    if not facts_artifact:
        return []
    blob = store.read(str(org_id), str(facts_artifact["id"]), facts_artifact["storage_key"])
    payload = json.loads(blob)
    return [
        NormalizedFact.model_validate(item)
        for item in payload
        if set(item) >= {"fact_id", "state"}
    ]
