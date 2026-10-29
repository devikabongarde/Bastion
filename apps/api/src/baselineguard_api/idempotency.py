from datetime import UTC, datetime, timedelta
from hashlib import sha256
from typing import Any

from baselineguard_persistence.models import IdempotencyKey
from baselineguard_rule_engine.canonical import canonical_json
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from baselineguard_api.errors import AppError
from baselineguard_api.security import Principal


def claim_request(
    db: Session,
    principal: Principal,
    route: str,
    key: str,
    body: dict[str, Any],
) -> dict[str, Any] | None:
    if not 16 <= len(key) <= 200 or any(ord(char) < 33 or ord(char) > 126 for char in key):
        raise AppError(
            422,
            "INVALID_IDEMPOTENCY_KEY",
            "Invalid request",
            "Idempotency-Key must contain 16–200 visible ASCII characters.",
        )
    digest = sha256(canonical_json(body)).hexdigest()
    now = datetime.now(UTC)
    stmt = (
        insert(IdempotencyKey)
        .values(
            org_id=principal.org_id,
            principal_id=principal.user_id,
            route=route,
            key=key,
            request_digest=digest,
            response_ref=None,
            expires_at=now + timedelta(hours=24),
        )
        .on_conflict_do_nothing(index_elements=["org_id", "principal_id", "route", "key"])
        .returning(IdempotencyKey.key)
    )
    inserted = db.execute(stmt).scalar_one_or_none()
    if inserted is not None:
        return None
    saved = db.execute(
        select(IdempotencyKey)
        .where(
            IdempotencyKey.org_id == principal.org_id,
            IdempotencyKey.principal_id == principal.user_id,
            IdempotencyKey.route == route,
            IdempotencyKey.key == key,
        )
        .with_for_update()
    ).scalar_one()
    if saved.expires_at <= now:
        saved.request_digest = digest
        saved.response_ref = None
        saved.expires_at = now + timedelta(hours=24)
        return None
    if saved.request_digest != digest:
        raise AppError(
            409,
            "IDEMPOTENCY_CONFLICT",
            "Request conflict",
            "This idempotency key was used with a different request.",
        )
    if saved.response_ref is None:
        raise AppError(
            409,
            "REQUEST_IN_PROGRESS",
            "Request in progress",
            "Retry this request after the original operation completes.",
            headers={"Retry-After": "1"},
        )
    return saved.response_ref


def save_response(
    db: Session, principal: Principal, route: str, key: str, response: dict[str, Any]
) -> None:
    saved = db.execute(
        select(IdempotencyKey)
        .where(
            IdempotencyKey.org_id == principal.org_id,
            IdempotencyKey.principal_id == principal.user_id,
            IdempotencyKey.route == route,
            IdempotencyKey.key == key,
        )
        .with_for_update()
    ).scalar_one()
    saved.response_ref = response
