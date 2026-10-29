from collections.abc import Iterable
from dataclasses import dataclass
from decimal import ROUND_HALF_UP, Decimal

from baselineguard_contracts.common import ResultStatus


@dataclass(frozen=True, slots=True)
class ScoreSummary:
    passed: int
    failed: int
    not_applicable: int
    unknown: int
    error: int
    manual_required: int
    evaluated_compliance_pct: Decimal | None
    assessment_completeness_pct: Decimal | None
    verified_conformance_pct: Decimal | None


def _percent(numerator: int, denominator: int) -> Decimal | None:
    if denominator == 0:
        return None
    return (Decimal(numerator) * 100 / Decimal(denominator)).quantize(
        Decimal("0.1"),
        rounding=ROUND_HALF_UP,
    )


def summarize(statuses: Iterable[ResultStatus]) -> ScoreSummary:
    counts = {status: 0 for status in ResultStatus}
    for status in statuses:
        counts[status] += 1
    passed = counts[ResultStatus.PASS]
    failed = counts[ResultStatus.FAIL]
    not_applicable = counts[ResultStatus.NOT_APPLICABLE]
    unknown = counts[ResultStatus.UNKNOWN]
    error = counts[ResultStatus.ERROR]
    manual = counts[ResultStatus.MANUAL_REQUIRED]
    assessable = passed + failed
    total = sum(counts.values())
    in_scope = total - not_applicable
    return ScoreSummary(
        passed=passed,
        failed=failed,
        not_applicable=not_applicable,
        unknown=unknown,
        error=error,
        manual_required=manual,
        evaluated_compliance_pct=_percent(passed, assessable),
        assessment_completeness_pct=_percent(assessable, in_scope),
        verified_conformance_pct=_percent(passed, in_scope),
    )
