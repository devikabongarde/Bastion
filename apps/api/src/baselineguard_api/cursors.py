import base64
import hmac
import json
from datetime import datetime
from hashlib import sha256
from typing import Any
from uuid import UUID

from baselineguard_rule_engine.canonical import canonical_json

from baselineguard_api.config import get_settings


class InvalidCursor(ValueError):
    pass


def _key() -> bytes:
    secret = get_settings().session_secret.get_secret_value().encode("utf-8")
    return hmac.new(secret, b"baselineguard/cursor/v1", sha256).digest()


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def encode_cursor(*, org_id: UUID, route: str, created_at: datetime, object_id: UUID) -> str:
    body = canonical_json(
        {
            "v": 1,
            "org_id": str(org_id),
            "route": route,
            "created_at": created_at.isoformat(),
            "id": str(object_id),
        }
    )
    signature = hmac.new(_key(), body, sha256).digest()
    return f"{_b64(body)}.{_b64(signature)}"


def decode_cursor(token: str, *, org_id: UUID, route: str) -> tuple[datetime, UUID]:
    if len(token) > 2048 or token.count(".") != 1:
        raise InvalidCursor
    body_part, signature_part = token.split(".")
    try:
        body = base64.urlsafe_b64decode(body_part + "=" * (-len(body_part) % 4))
        signature = base64.urlsafe_b64decode(signature_part + "=" * (-len(signature_part) % 4))
        expected = hmac.new(_key(), body, sha256).digest()
        if not hmac.compare_digest(signature, expected):
            raise InvalidCursor
        payload: Any = json.loads(body)
        if payload != {
            "v": 1,
            "org_id": str(org_id),
            "route": route,
            "created_at": payload["created_at"],
            "id": payload["id"],
        }:
            raise InvalidCursor
        return datetime.fromisoformat(payload["created_at"]), UUID(payload["id"])
    except (ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        raise InvalidCursor from exc
