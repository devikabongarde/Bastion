from decimal import Decimal

from baselineguard_contracts.common import ResultStatus
from baselineguard_domain.scoring import summarize


def test_score_formulas_match_the_prd_example() -> None:
    statuses = (
        [ResultStatus.PASS] * 60
        + [ResultStatus.FAIL] * 20
        + [ResultStatus.NOT_APPLICABLE] * 5
        + [ResultStatus.UNKNOWN] * 10
        + [ResultStatus.ERROR] * 3
        + [ResultStatus.MANUAL_REQUIRED] * 2
    )
    score = summarize(statuses)
    assert score.evaluated_compliance_pct == Decimal("75.0")
    assert score.assessment_completeness_pct == Decimal("84.2")
    assert score.verified_conformance_pct == Decimal("63.2")
    assert (score.passed, score.failed, score.not_applicable) == (60, 20, 5)


def test_empty_assessment_has_no_invented_score() -> None:
    score = summarize([])
    assert score.evaluated_compliance_pct is None
    assert score.assessment_completeness_pct is None
    assert score.verified_conformance_pct is None


def test_inapplicable_only_assessment_has_no_compliance_denominator() -> None:
    score = summarize([ResultStatus.NOT_APPLICABLE] * 3)
    assert score.not_applicable == 3
    assert score.evaluated_compliance_pct is None
    assert score.assessment_completeness_pct is None
