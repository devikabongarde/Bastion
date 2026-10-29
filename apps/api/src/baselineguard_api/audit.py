from datetime import datetime
from hashlib import sha256
from typing import Any, cast
from uuid import UUID, uuid4

from baselineguard_persistence.models import AuditEvent
from baselineguard_rule_engine.canonical import canonical_json
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from baselineguard_api.security import Principal

ZERO_HASH = "0" * 64


def append_audit_event(
    db: Session,
    principal: Principal,
    *,
    action: str,
    object_type: str,
    object_id: UUID | None,
    details: dict[str, Any],
) -> AuditEvent:
    # Serialize the sequence without granting the runtime role write access to organizations.
    db.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended(:org_key, 0))"),
        {"org_key": str(principal.org_id)},
    )
    previous = db.execute(
        select(AuditEvent)
        .where(AuditEvent.org_id == principal.org_id)
        .order_by(AuditEvent.sequence.desc())
        .limit(1)
    ).scalar_one_or_none()
    sequence = (previous.sequence + 1) if previous else 1
    previous_hash = previous.event_hash if previous else ZERO_HASH
    event_id = uuid4()
    timestamp = cast(datetime, db.execute(select(text("clock_timestamp()"))).scalar_one())
    payload: dict[str, Any] = {
        "id": str(event_id),
        "org_id": str(principal.org_id),
        "sequence": sequence,
        "actor_id": str(principal.user_id),
        "action": action,
        "object_type": object_type,
        "object_id": str(object_id) if object_id else None,
        "redacted_details": details,
        "previous_hash": previous_hash,
        "occurred_at": timestamp.isoformat(),
    }
    digest = sha256(canonical_json(payload)).hexdigest()
    event = AuditEvent(
        id=event_id,
        org_id=principal.org_id,
        sequence=sequence,
        actor_id=principal.user_id,
        action=action,
        object_type=object_type,
        object_id=object_id,
        redacted_details=details,
        previous_hash=previous_hash,
        event_hash=digest,
        occurred_at=timestamp,
    )
    db.add(event)
    db.flush()
    return event
