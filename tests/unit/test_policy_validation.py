import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from baselineguard_contracts.policies import ControlOverride, PolicySpec
from baselineguard_rule_engine.canonical import semantic_digest

from baselineguard_api.errors import AppError
from baselineguard_api.routes.v1.policies import validate_spec

PACK_PATH = Path(__file__).parents[2] / "content" / "original" / "phase1-linux.yaml"


def _pack():
    manifest = json.loads(PACK_PATH.read_text(encoding="utf-8"))
    return SimpleNamespace(state="approved", manifest=manifest, digest=semantic_digest(manifest))


def test_policy_validation_reports_source_exclusion_and_override_coverage():
    pack = _pack()
    first_control = pack.manifest["controls"][0]["id"]
    spec = PolicySpec(
        overrides={first_control: ControlOverride(severity="critical", reason="Reviewed risk")},
        exclusions={pack.manifest["controls"][1]["id"]: "Not used on this approved image"},
    )

    assert validate_spec(spec, [pack]) == {
        "source_controls": len(pack.manifest["controls"]),
        "selected_controls": len(pack.manifest["controls"]) - 1,
        "excluded_controls": 1,
        "customized_controls": 1,
    }


def test_policy_rejects_unknown_control_ids():
    spec = PolicySpec(exclusions={"missing.control": "Not applicable in this environment"})

    with pytest.raises(AppError) as error:
        validate_spec(spec, [_pack()])

    assert error.value.code == "UNKNOWN_CONTROL"


def test_policy_rejects_pack_tampering_or_unapproved_content():
    pack = _pack()
    pack.digest = "0" * 64

    with pytest.raises(AppError) as error:
        validate_spec(PolicySpec(), [pack])

    assert error.value.code == "POLICY_CONTENT_UNAVAILABLE"
