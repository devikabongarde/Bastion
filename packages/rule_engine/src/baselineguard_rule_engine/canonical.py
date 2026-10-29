import hashlib
import json
from typing import Any, cast


def canonical_json(value: Any) -> bytes:
    """Stable JSON encoding; reject floats so cross-runtime rounding is explicit."""

    def validate(node: Any) -> None:
        if isinstance(node, float):
            raise TypeError(
                "floating point values are not valid canonical inputs; use decimal strings"
            )
        if isinstance(node, dict):
            for key, item in cast(dict[Any, Any], node).items():
                if not isinstance(key, str):
                    raise TypeError("canonical object keys must be strings")
                validate(item)
        elif isinstance(node, (list, tuple)):
            for item in cast(list[Any] | tuple[Any, ...], node):
                validate(item)

    validate(value)
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def semantic_digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()
