"""Policy resolution (PRD 9.4): apply a published policy revision to a rule pack.

Allowed customization is limited to typed parameter overrides, organization
severity overrides and excluded controls. Excluded controls remain accounted
for in the source-profile coverage view; a tailored view excludes them from
its own denominator and records the count.
"""

from __future__ import annotations

from typing import Any, cast


class PolicyResolutionError(ValueError):
    pass


def resolve_parameters(pack: dict[str, Any], spec: dict[str, Any]) -> dict[str, Any]:
    pack_parameters = cast(dict[str, Any], pack.get("parameters") or {})
    overrides = cast(list[dict[str, Any]], spec.get("overrides") or [])
    parameters: dict[str, Any] = {
        name: schema["default"]
        for name, schema in pack_parameters.items()
        if isinstance(schema, dict) and "default" in schema
    }
    for override in overrides:
        if override.get("kind") == "parameter":
            name = override["parameter"]
            if name not in pack_parameters:
                raise PolicyResolutionError(f"unknown parameter override: {name}")
            parameters[name] = override["value"]
    return parameters


def _freeze_severity(control: dict[str, Any], spec: dict[str, Any]) -> None:
    overrides = cast(list[dict[str, Any]], spec.get("overrides") or [])
    for override in overrides:
        if (
            override.get("kind") == "severity"
            and override.get("control_key") == control["id"]
        ):
            value = override.get("value")
            if value in {"critical", "high", "medium", "low"}:
                control["severity"] = value
            else:
                raise PolicyResolutionError(f"invalid severity override: {value!r}")


def _freeze_parameters(expression: Any, parameters: dict[str, Any]) -> Any:
    """Replace {"parameter": name} leaves with frozen typed values, recursively."""
    if isinstance(expression, dict):
        mapping = cast(dict[str, Any], expression)
        if set(mapping) == {"parameter"}:
            name = str(mapping["parameter"])
            if name not in parameters:
                raise PolicyResolutionError(f"unresolved parameter reference: {name}")
            return parameters[name]
        return {
            key: _freeze_parameters(value, parameters) for key, value in mapping.items()
        }
    if isinstance(expression, list):
        return [
            _freeze_parameters(item, parameters)
            for item in cast(list[Any], expression)
        ]
    return expression


def resolve_controls(
    pack: dict[str, Any],
    spec: dict[str, Any],
) -> dict[str, Any]:
    """Return the frozen control list and resolution metadata for one run."""
    parameters = resolve_parameters(pack, spec)
    excluded = set(cast(list[str], spec.get("excluded_control_keys") or []))
    frozen: list[dict[str, Any]] = []
    inventory: list[dict[str, Any]] = []
    controls = cast(list[dict[str, Any]], pack["controls"])
    for control in controls:
        bare = {key: value for key, value in control.items() if key != "tests"}
        is_excluded = control["id"] in excluded
        inventory.append({"control_key": control["id"], "excluded": is_excluded})
        if is_excluded:
            continue
        _freeze_severity(bare, spec)
        bare["assertion"] = _freeze_parameters(bare["assertion"], parameters)
        bare["applicability"] = _freeze_parameters(bare["applicability"], parameters)
        frozen.append(bare)
    return {
        "parameters": parameters,
        "excluded_keys": sorted(excluded),
        "excluded_count": len(excluded),
        "controls": frozen,
        "full_inventory": inventory,
        "accounted_recommendations": len(inventory),
    }
