from pathlib import Path

import pytest
from baselineguard_contracts.common import NormalizedFact
from baselineguard_rule_engine.canonical import canonical_json, semantic_digest
from baselineguard_rule_engine.evaluator import evaluate_control
from baselineguard_rule_engine.logic import Truth, tri_all, tri_any, tri_not
from baselineguard_rule_engine.packs import DuplicateKeyError, load_rule_pack

PACK_PATH = Path(__file__).resolve().parents[2] / "content" / "original" / "phase1-linux.yaml"


@pytest.fixture(scope="module")
def pack() -> dict:
    return load_rule_pack(PACK_PATH.read_bytes())


def test_phase1_original_pack_is_valid_and_has_twenty_controls(pack: dict) -> None:
    assert len(pack["controls"]) == 20
    assert {control["origin"] for control in pack["controls"]} == {"organizational"}
    assert all(control.get("source_mapping") is None for control in pack["controls"])


@pytest.mark.parametrize("fixture_name", ["conforming", "deviation", "unavailable", "other-family"])
def test_each_original_control_fixture_matches_its_expected_result(
    pack: dict, fixture_name: str
) -> None:
    expected_by_name = {
        "conforming": "PASS",
        "deviation": "FAIL",
        "unavailable": "UNKNOWN",
        "other-family": "NOT_APPLICABLE",
    }
    for control in pack["controls"]:
        fixture = next(item for item in control["tests"] if item["id"] == fixture_name)
        assert fixture["expect"] == expected_by_name[fixture_name]
        facts = {
            key: NormalizedFact(fact_id=key, **value) for key, value in fixture["facts"].items()
        }
        result = evaluate_control(control, facts)
        assert result["status"] == fixture["expect"], control["id"]


def test_collection_failure_is_error_and_never_a_pass(pack: dict) -> None:
    result = evaluate_control(pack["controls"][0], {}, collection_error=True)
    assert result["status"] == "ERROR"
    assert result["reason_code"] == "COLLECTION_FAILED"


def test_control_evaluation_has_100_deterministic_replays(pack: dict) -> None:
    control = pack["controls"][0]
    fixture = next(item for item in control["tests"] if item["id"] == "deviation")
    facts = {key: NormalizedFact(fact_id=key, **value) for key, value in fixture["facts"].items()}
    expected = canonical_json(evaluate_control(control, facts))
    assert all(canonical_json(evaluate_control(control, facts)) == expected for _ in range(100))


def test_three_valued_logic_preserves_unknown() -> None:
    assert tri_not(Truth.UNKNOWN) is Truth.UNKNOWN
    assert tri_all([Truth.TRUE, Truth.UNKNOWN]) is Truth.UNKNOWN
    assert tri_all([Truth.FALSE, Truth.UNKNOWN]) is Truth.FALSE
    assert tri_any([Truth.FALSE, Truth.UNKNOWN]) is Truth.UNKNOWN
    assert tri_any([Truth.TRUE, Truth.UNKNOWN]) is Truth.TRUE
    assert tri_all([]) is Truth.UNKNOWN
    assert tri_any([]) is Truth.UNKNOWN


def test_yaml_duplicate_keys_are_rejected_before_schema_evaluation() -> None:
    with pytest.raises(DuplicateKeyError):
        load_rule_pack(b"schema_version: '1.0'\nschema_version: '1.0'\n")


def test_yaml_executable_tags_are_rejected() -> None:
    with pytest.raises(ValueError, match="valid UTF-8 YAML"):
        load_rule_pack(b"!!python/object/apply:os.system ['whoami']")


def test_recursive_yaml_aliases_are_rejected() -> None:
    with pytest.raises(ValueError, match="recursive YAML aliases"):
        load_rule_pack(b"root: &root [*root]")


def test_canonical_json_is_stable_and_rejects_float_ambiguity() -> None:
    assert canonical_json({"b": 1, "a": "x"}) == b'{"a":"x","b":1}'
    assert semantic_digest({"x": [2, 1]}) == semantic_digest({"x": [2, 1]})
    with pytest.raises(TypeError, match="floating point"):
        canonical_json({"threshold": 0.1})
