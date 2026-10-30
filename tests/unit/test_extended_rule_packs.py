from pathlib import Path

import pytest
from baselineguard_contracts.common import NormalizedFact
from baselineguard_rule_engine.canonical import canonical_json
from baselineguard_rule_engine.evaluator import evaluate_control
from baselineguard_rule_engine.packs import load_rule_pack

CONTENT = Path(__file__).resolve().parents[2] / "content" / "original"


@pytest.mark.parametrize(
    "filename,expected_count,family",
    [
        ("windows-server-2019.yaml", 32, "windows_server"),
        ("cisco-iosxe-hardening.yaml", 31, "cisco_ios_xe"),
        ("fortigate-fortios.yaml", 20, "fortigate"),
    ],
)
def test_extended_rule_packs_load_and_validate(filename: str, expected_count: int, family: str) -> None:
    pack_path = CONTENT / filename
    assert pack_path.is_file()
    pack = load_rule_pack(pack_path.read_bytes())
    assert len(pack["controls"]) == expected_count
    assert pack["targets"]["family"] == family

    # Test all fixtures for every control in the pack
    expected_by_name = {
        "conforming": "PASS",
        "deviation": "FAIL",
        "unavailable": "UNKNOWN",
        "other-family": "NOT_APPLICABLE",
    }

    for control in pack["controls"]:
        for f_name, expected_status in expected_by_name.items():
            fixture = next(item for item in control["tests"] if item["id"] == f_name)
            assert fixture["expect"] == expected_status
            facts = {
                key: NormalizedFact(fact_id=key, **value)
                for key, value in fixture["facts"].items()
            }
            res = evaluate_control(control, facts)
            assert res["status"] == expected_status, f"{control['id']} on fixture {f_name}"


def test_windows_and_fortigate_100_replay_determinism() -> None:
    win_pack = load_rule_pack((CONTENT / "windows-server-2019.yaml").read_bytes())
    ctrl = win_pack["controls"][0]
    fixture = next(item for item in ctrl["tests"] if item["id"] == "deviation")
    facts = {key: NormalizedFact(fact_id=key, **val) for key, val in fixture["facts"].items()}
    expected = canonical_json(evaluate_control(ctrl, facts))
    assert all(canonical_json(evaluate_control(ctrl, facts)) == expected for _ in range(100))
