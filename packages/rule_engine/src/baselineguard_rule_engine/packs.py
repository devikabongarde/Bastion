from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

import jsonschema
import yaml
from yaml.nodes import MappingNode

MAX_PACK_BYTES = 1_048_576
MAX_DEPTH = 32
MAX_NODES = 10_000
SCHEMA_PATH = Path(__file__).resolve().parents[4] / "content" / "schemas" / "rule-pack.schema.json"


class DuplicateKeyError(ValueError):
    pass


class UniqueKeySafeLoader(yaml.SafeLoader):
    def construct_mapping(self, node: MappingNode, deep: bool = False) -> dict[Any, Any]:
        self.flatten_mapping(node)
        result: dict[Any, Any] = {}
        for key_node, value_node in node.value:
            key: Any = cast(Any, self.construct_object(key_node, deep=deep))
            try:
                duplicate = key in result
            except TypeError as exc:
                raise DuplicateKeyError(
                    "rule pack mapping keys must be scalar and hashable"
                ) from exc
            if duplicate:
                raise DuplicateKeyError(f"duplicate rule pack key: {key}")
            result[key] = self.construct_object(value_node, deep=deep)
        return result


def _guard_tree(value: Any, *, active: set[int], depth: int, count: list[int]) -> None:
    if depth > MAX_DEPTH:
        raise ValueError("rule pack nesting exceeds the maximum depth")
    count[0] += 1
    if count[0] > MAX_NODES:
        raise ValueError("rule pack exceeds the maximum node count")
    if isinstance(value, (dict, list)):
        identity = id(value)
        if identity in active:
            raise ValueError("recursive YAML aliases are not allowed")
        active.add(identity)
        if isinstance(value, dict):
            for key, child in cast(dict[Any, Any], value).items():
                _guard_tree(key, active=active, depth=depth + 1, count=count)
                _guard_tree(child, active=active, depth=depth + 1, count=count)
        else:
            for index, child in enumerate(cast(list[Any], value)):
                _guard_tree(index, active=active, depth=depth + 1, count=count)
                _guard_tree(child, active=active, depth=depth + 1, count=count)
        active.remove(identity)


def load_rule_pack(content: bytes, schema: dict[str, Any] | None = None) -> dict[str, Any]:
    if len(content) > MAX_PACK_BYTES:
        raise ValueError("rule pack exceeds the one mebibyte import limit")
    try:
        # This loader subclasses SafeLoader and only overrides duplicate-key handling.
        pack = yaml.load(content.decode("utf-8"), Loader=UniqueKeySafeLoader)  # noqa: S506
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        raise ValueError("rule pack is not valid UTF-8 YAML") from exc
    if not isinstance(pack, dict):
        raise ValueError("rule pack root must be a mapping")
    _guard_tree(pack, active=set(), depth=0, count=[0])
    if schema is None:
        loaded_schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        if not isinstance(loaded_schema, dict):
            raise ValueError("rule pack schema root must be an object")
        schema = cast(dict[str, Any], loaded_schema)
    jsonschema.Draft202012Validator.check_schema(schema)
    validator = jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker())
    errors = sorted(
        validator.iter_errors(pack), key=lambda error: tuple(str(part) for part in error.path)
    )
    if errors:
        first = errors[0]
        location = ".".join(str(part) for part in first.path) or "root"
        raise ValueError(f"invalid rule pack at {location}: {first.message}")
    pack = cast(dict[str, Any], pack)
    controls: list[dict[str, Any]] = pack["controls"]
    keys = [str(control["id"]) for control in controls]
    if len(set(keys)) != len(keys):
        raise ValueError("control identifiers must be unique within a rule pack")
    for control in controls:
        if control["origin"] == "cis_mapped" and "source_mapping" not in control:
            raise ValueError("CIS-mapped controls require a reviewed source mapping")
        if control["origin"] != "cis_mapped" and "source_mapping" in control:
            raise ValueError("source mappings are only accepted for controls labeled cis_mapped")
        node_count = [0]
        _validate_expression(control["assertion"], 0, node_count)
        _validate_expression(control["applicability"], 0, node_count)
    return pack


def _validate_expression(expression: dict[str, Any], depth: int, count: list[int]) -> None:
    count[0] += 1
    if depth >= MAX_DEPTH or count[0] > MAX_NODES:
        raise ValueError("rule expression exceeds its execution bounds")
    operator = expression["op"]
    if operator in {"and", "or"}:
        for child in expression["args"]:
            _validate_expression(child, depth + 1, count)
    elif operator == "not":
        _validate_expression(expression["arg"], depth + 1, count)
