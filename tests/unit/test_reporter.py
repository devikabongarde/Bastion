import csv
import hashlib
import io
import json
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from baselineguard_contracts.common import EvidencePointer, ResultStatus

from baselineguard_reporter import (
    ReportDocument,
    ReportFinding,
    render_csv,
    render_html,
    render_json,
    render_report,
)

NOW = datetime(2026, 10, 29, 10, 0, tzinfo=UTC)


def report_fixture() -> ReportDocument:
    return ReportDocument(
        report_id=uuid4(),
        organization_id=uuid4(),
        organization_name="<North & West>",
        requester_id=uuid4(),
        created_at=NOW,
        assessment_cutoff=NOW,
        policy_id=uuid4(),
        policy_name="Baseline <one>",
        policy_revision=3,
        policy_digest="a" * 64,
        engine_digest="b" * 64,
        scope={"site_ids": ["site-1"], "token": "do-not-export"},
        completeness={"pass": 1, "fail": 1, "unknown": 1},
        findings=(
            ReportFinding(
                asset_id=uuid4(),
                asset_name='=HYPERLINK("https://example.invalid")',
                context_key="global",
                control_key="org.test.credential",
                origin="organizational",
                severity="high",
                status=ResultStatus.FAIL,
                reason_code="ASSERTION_FAILED",
                expected={"auth": {"secret": "hidden"}},
                actual={
                    "value": "unsafe",
                    "password": "do-not-export",
                    "reader_excerpt": "password = canary-secret-value",
                },
                evidence=(
                    EvidencePointer(
                        artifact_sha256="c" * 64,
                        reader_id="reader.test",
                        pointer={"line": 3, "token": "pointer-canary-secret"},
                        redaction_version="1",
                    ),
                ),
                remediation_status="manual_procedure_required",
                remediation_procedure="<script>alert(1)</script> password=procedure-canary-secret",
            ),
            ReportFinding(
                asset_id=uuid4(),
                asset_name="server-02",
                context_key="global",
                control_key="org.test.missing",
                origin="organizational",
                severity="medium",
                status=ResultStatus.UNKNOWN,
                reason_code="REQUIRED_EVIDENCE_UNAVAILABLE",
                expected={"value": "enabled"},
            ),
        ),
        omissions=("CIS rights review is pending",),
    )


def test_json_report_is_canonical_complete_and_redacts_nested_secrets():
    report = report_fixture()

    first = render_json(report)
    second = render_json(report)
    body = json.loads(first)

    assert first == second
    assert body["schema_version"] == "1.0"
    assert len(body["findings"]) == 2
    assert body["findings"][0]["expected"]["auth"]["secret"] == "[REDACTED]"
    assert body["findings"][0]["actual"]["password"] == "[REDACTED]"
    assert "canary-secret-value" not in first.decode("utf-8")
    assert "pointer-canary-secret" not in first.decode("utf-8")
    assert "procedure-canary-secret" not in first.decode("utf-8")
    assert body["scope"]["token"] == "[REDACTED]"
    assert b"do-not-export" not in first


def test_csv_has_one_row_per_result_and_neutralizes_formula_cells():
    report = report_fixture()
    rows = list(csv.DictReader(io.StringIO(render_csv(report).decode("utf-8"))))

    assert len(rows) == len(report.findings)
    assert rows[0]["asset_name"].startswith("'=")
    assert rows[0]["expected_json"] == '{"auth": {"secret": "[REDACTED]"}}'
    assert "do-not-export" not in render_csv(report).decode("utf-8")
    assert "canary-secret-value" not in render_csv(report).decode("utf-8")
    assert "pointer-canary-secret" not in render_csv(report).decode("utf-8")
    assert "procedure-canary-secret" not in render_csv(report).decode("utf-8")


def test_html_is_escaped_self_contained_and_has_all_result_rows():
    document = render_html(report_fixture()).decode("utf-8")

    assert "<script>alert(1)</script>" not in document
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in document
    assert "procedure-canary-secret" not in document
    assert "pointer-canary-secret" not in document
    assert "&lt;North &amp; West&gt;" in document
    assert "default-src 'none'" in document
    assert 'href="https://example.invalid"' not in document
    assert "<script src=" not in document
    assert document.count("<tr>") == 3


def test_rendered_artifacts_include_content_hash_and_size():
    report = report_fixture()
    artifacts = render_report(report, ("json", "html", "csv"))

    assert [artifact.format for artifact in artifacts] == ["json", "html", "csv"]
    for artifact in artifacts:
        assert artifact.byte_length == len(artifact.content)
        assert artifact.sha256 == hashlib.sha256(artifact.content).hexdigest()


def test_report_rejects_naive_timestamps_and_duplicate_formats():
    values = report_fixture().model_dump()
    values["created_at"] = datetime(2026, 10, 29)

    with pytest.raises(ValueError, match="UTC"):
        ReportDocument(**values)

    with pytest.raises(ValueError, match="unique"):
        render_report(report_fixture(), ("json", "json"))


def test_report_rejects_ambiguous_float_canonical_values():
    values = report_fixture().model_dump()
    values["scope"] = {"threshold": 0.1}
    report = ReportDocument(**values)

    with pytest.raises(TypeError, match="floating point"):
        render_csv(report)
