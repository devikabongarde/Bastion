from __future__ import annotations

from typing import Any

from baselineguard_contracts.common import FactState, NormalizedFact, ResultStatus

from baselineguard_rule_engine.logic import Truth, tri_all, tri_any, tri_not

MAX_EVALUATION_STEPS = 100_000


def _fact_value(fact: NormalizedFact | None) -> tuple[Truth, Any]:
    if fact is None:
        return Truth.UNKNOWN, None
    if fact.state is not FactState.PRESENT:
        return Truth.UNKNOWN, None
    return Truth.TRUE, fact.value


def evaluate_expression(
    expression: dict[str, Any],
    facts: dict[str, NormalizedFact],
    *,
    steps: list[int] | None = None,
) -> Truth:
    counter = steps if steps is not None else [0]
    counter[0] += 1
    if counter[0] > MAX_EVALUATION_STEPS:
        raise RuntimeError("EVALUATION_LIMIT")
    op = expression["op"]
    if op == "and":
        return tri_all(
            evaluate_expression(child, facts, steps=counter) for child in expression["args"]
        )
    if op == "or":
        return tri_any(
            evaluate_expression(child, facts, steps=counter) for child in expression["args"]
        )
    if op == "not":
        return tri_not(evaluate_expression(expression["arg"], facts, steps=counter))

    available, actual = _fact_value(facts.get(expression["fact"]))
    if available is Truth.UNKNOWN:
        return Truth.UNKNOWN
    expected = expression["value"]
    try:
        if op == "eq":
            value = actual == expected
        elif op == "ne":
            value = actual != expected
        elif op == "lt":
            value = actual < expected
        elif op == "lte":
            value = actual <= expected
        elif op == "gt":
            value = actual > expected
        elif op == "gte":
            value = actual >= expected
        elif op == "in":
            value = actual in expected
        elif op == "contains":
            value = expected in actual
        else:
            raise ValueError("unsupported rule operator")
    except (TypeError, ValueError):
        return Truth.UNKNOWN
    return Truth.TRUE if value else Truth.FALSE


def evaluate_control(
    control: dict[str, Any],
    facts: dict[str, NormalizedFact],
    *,
    collection_error: bool = False,
) -> dict[str, Any]:
    if collection_error:
        status = ResultStatus.ERROR
        reason = "COLLECTION_FAILED"
    else:
        applicability = evaluate_expression(control["applicability"], facts)
        if applicability is Truth.FALSE:
            status, reason = ResultStatus.NOT_APPLICABLE, "NOT_APPLICABLE"
        elif applicability is Truth.UNKNOWN:
            status, reason = ResultStatus.UNKNOWN, "APPLICABILITY_UNRESOLVED"
        else:
            missing = [key for key in control["required_facts"] if key not in facts]
            unavailable = [
                key
                for key in control["required_facts"]
                if key in facts and facts[key].state is not FactState.PRESENT
            ]
            if missing or unavailable:
                status, reason = ResultStatus.UNKNOWN, "REQUIRED_EVIDENCE_UNAVAILABLE"
            else:
                assertion = evaluate_expression(control["assertion"], facts)
                if assertion is Truth.TRUE:
                    status, reason = ResultStatus.PASS, "ASSERTION_SATISFIED"
                elif assertion is Truth.FALSE:
                    status, reason = ResultStatus.FAIL, "ASSERTION_FAILED"
                else:
                    status, reason = ResultStatus.UNKNOWN, "ASSERTION_UNRESOLVED"
    return {
        "control_key": control["id"],
        "status": status.value,
        "reason_code": reason,
        "expected": control["expected"],
        "actual": {
            key: facts[key].value
            for key in control["required_facts"]
            if key in facts and facts[key].state is FactState.PRESENT
        },
        "severity": control["severity"],
        "assessment_quality": "proven"
        if status in {ResultStatus.PASS, ResultStatus.FAIL, ResultStatus.NOT_APPLICABLE}
        else "incomplete",
    }
