from __future__ import annotations

import csv
import hashlib
import html
import io
import json
import re
from datetime import UTC, datetime
from typing import Annotated, Any, Literal, cast
from uuid import UUID

from baselineguard_contracts.common import Contract, EvidencePointer, Identifier, ResultStatus
from baselineguard_rule_engine.canonical import canonical_json
from pydantic import Field, field_validator

SENSITIVE_KEYS = frozenset(
    {
        "password",
        "passwd",
        "secret",
        "token",
        "community",
        "private_key",
        "privatekey",
        "authorization",
        "credential",
        "credential_value",
        "pre_shared_key",
    }
)
CSV_COLUMNS = (
    "asset_id",
    "asset_name",
    "context_key",
    "control_key",
    "origin",
    "source_reference",
    "severity",
    "status",
    "reason_code",
    "aggregate",
    "expected_json",
    "actual_json",
    "evidence_json",
    "remediation_status",
    "remediation_procedure",
)
SECRET_ASSIGNMENT = re.compile(
    r"(?i)(\b(?:password|passwd|secret|token|community|authorization|private[-_ ]?key|"
    r"pre[-_ ]?shared[-_ ]?key)\b\s*[:=]\s*)(\"[^\"]*\"|'[^']*'|[^\s,;]+)"
)
PRIVATE_KEY_BLOCK = re.compile(
    r"(?s)-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----"
)


class ReportFinding(Contract):
    asset_id: UUID
    asset_name: str = Field(min_length=1, max_length=255)
    context_key: Identifier
    control_key: Identifier
    origin: Literal["organizational", "cis_mapped", "vendor_guidance"]
    source_reference: str | None = Field(default=None, max_length=256)
    severity: Literal["critical", "high", "medium", "low"]
    status: ResultStatus
    reason_code: Identifier
    aggregate: bool = True
    expected: dict[str, Any]
    actual: Any | None = None
    evidence: tuple[EvidencePointer, ...] = ()
    remediation_status: Literal["ready_to_review", "manual_procedure_required", "unavailable"] = (
        "unavailable"
    )
    remediation_procedure: str | None = Field(default=None, max_length=20000)


class ReportDocument(Contract):
    schema_version: Literal["1.0"] = "1.0"
    report_id: UUID
    organization_id: UUID
    organization_name: str = Field(min_length=1, max_length=255)
    requester_id: UUID
    created_at: datetime
    assessment_cutoff: datetime
    policy_id: UUID
    policy_name: str = Field(min_length=1, max_length=255)
    policy_revision: int = Field(ge=1)
    policy_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    engine_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    scope: dict[str, Any]
    completeness: dict[str, Annotated[int, Field(ge=0, le=10_000_000)]] = Field(max_length=64)
    findings: tuple[ReportFinding, ...] = Field(max_length=500_000)
    omissions: tuple[str, ...] = Field(default_factory=tuple, max_length=10_000)

    @field_validator("created_at", "assessment_cutoff")
    @classmethod
    def require_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() != UTC.utcoffset(value):
            raise ValueError("Report timestamps must be timezone-aware UTC values")
        return value


class RenderedArtifact(Contract):
    format: Literal["json", "html", "csv"]
    media_type: str
    filename: str
    byte_length: int = Field(ge=0)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    content: bytes


def _redact(value: Any, *, key: str | None = None) -> Any:
    """Redact secret-like mapping keys recursively before creating any format."""
    if key is not None and key.casefold() in SENSITIVE_KEYS:
        return "[REDACTED]"
    if isinstance(value, dict):
        items = cast(dict[str, Any], value).items()
        return {str(item_key): _redact(item, key=str(item_key)) for item_key, item in items}
    if isinstance(value, (tuple, list)):
        return [_redact(item) for item in cast(list[Any] | tuple[Any, ...], value)]
    if isinstance(value, str):
        value = PRIVATE_KEY_BLOCK.sub("[REDACTED PRIVATE KEY]", value)
        return SECRET_ASSIGNMENT.sub(r"\1[REDACTED]", value)
    return value


def _document(report: ReportDocument) -> dict[str, Any]:
    return _redact(report.model_dump(mode="json"))


def _redact_text(value: str) -> str:
    redacted = _redact(value)
    if not isinstance(redacted, str):
        raise TypeError("text redaction returned a non-text value")
    return redacted


def render_json(report: ReportDocument) -> bytes:
    """Render the complete versioned machine document with stable key ordering."""
    return canonical_json(_document(report))


def _cell(value: str) -> str:
    """Prevent spreadsheet formula execution in untrusted text fields."""
    if value.startswith(("=", "+", "-", "@", "\t", "\r")):
        return "'" + value
    return value


def render_csv(report: ReportDocument) -> bytes:
    canonical_json(_document(report))
    output = io.StringIO(newline="")
    writer: csv.DictWriter[Any] = csv.DictWriter(
        output,
        fieldnames=list(CSV_COLUMNS),
        extrasaction="raise",
        lineterminator="\r\n",
        quoting=csv.QUOTE_MINIMAL,
    )
    writer.writeheader()
    for finding in report.findings:
        row: dict[str, str] = {
            "asset_id": str(finding.asset_id),
            "asset_name": finding.asset_name,
            "context_key": finding.context_key,
            "control_key": finding.control_key,
            "origin": finding.origin,
            "source_reference": _redact_text(finding.source_reference or ""),
            "severity": finding.severity,
            "status": finding.status.value,
            "reason_code": finding.reason_code,
            "aggregate": "true" if finding.aggregate else "false",
            "expected_json": json.dumps(
                _redact(finding.expected), ensure_ascii=False, sort_keys=True
            ),
            "actual_json": json.dumps(_redact(finding.actual), ensure_ascii=False, sort_keys=True),
            "evidence_json": json.dumps(
                _redact([pointer.model_dump(mode="json") for pointer in finding.evidence]),
                ensure_ascii=False,
                sort_keys=True,
            ),
            "remediation_status": finding.remediation_status,
            "remediation_procedure": _redact_text(finding.remediation_procedure or ""),
        }
        writer.writerow({key: _cell(value) for key, value in row.items()})
    return output.getvalue().encode("utf-8")


HTML_STYLE = """
body { font: 15px/1.5 system-ui,sans-serif; color:#202b2b; background:#faf9f6; }
body { margin:2rem auto; max-width:1120px; padding:0 1.25rem; }
h1,h2 { line-height:1.2; color:#183b37; }
h1 { font-size:1.9rem; }
h2 { font-size:1.25rem; margin-top:2rem; }
.meta { color:#526360; }
.summary { display:flex; gap:1rem; flex-wrap:wrap; padding:1rem 0; }
.summary { border-block:1px solid #d7ded9; }
.summary span { font-variant-numeric:tabular-nums; }
table { border-collapse:collapse; width:100%; margin:1rem 0; font-size:.9rem; }
th,td { border-bottom:1px solid #d7ded9; text-align:left; padding:.55rem .65rem; }
th,td { vertical-align:top; }
th { background:#edf1ed; color:#183b37; }
code,pre { font-family:ui-monospace,monospace; white-space:pre-wrap; }
code,pre { overflow-wrap:anywhere; }
.omissions { border-left:4px solid #a46a20; padding:.25rem 1rem; }
@media print {
 body { max-width:none; margin:0; color:#111; background:#fff; }
 thead { display:table-header-group; }
 tr { break-inside:avoid; }
}
""".strip()


def render_html(report: ReportDocument) -> bytes:
    """Render a self-contained, escaped, offline HTML report without remote resources."""
    canonical_json(_document(report))
    summary: dict[str, int] = {}
    for finding in report.findings:
        summary[finding.status.value] = summary.get(finding.status.value, 0) + 1
    summary_rows = "".join(
        f"<span><strong>{html.escape(status)}</strong>: {count}</span>"
        for status, count in sorted(summary.items())
    )
    rows: list[str] = []
    for finding in report.findings:
        expected = json.dumps(_redact(finding.expected), ensure_ascii=False, sort_keys=True)
        actual = json.dumps(_redact(finding.actual), ensure_ascii=False, sort_keys=True)
        evidence = json.dumps(
            _redact([pointer.model_dump(mode="json") for pointer in finding.evidence]),
            ensure_ascii=False,
            sort_keys=True,
        )
        cells = (
            finding.asset_name,
            finding.control_key,
            finding.severity,
            finding.status.value,
            finding.reason_code,
            expected,
            actual,
            evidence,
            finding.remediation_status,
            _redact_text(finding.remediation_procedure or ""),
        )
        rows.append(
            "<tr>" + "".join(f"<td>{html.escape(str(cell))}</td>" for cell in cells) + "</tr>"
        )
    omissions = "".join(f"<li>{html.escape(item)}</li>" for item in report.omissions)
    omission_section = (
        f'<section class="omissions" aria-labelledby="omissions-heading">'
        f'<h2 id="omissions-heading">Omissions and limitations</h2><ul>{omissions}</ul></section>'
        if omissions
        else ""
    )
    completeness = html.escape(json.dumps(report.completeness, ensure_ascii=False, sort_keys=True))
    scope_json = html.escape(
        json.dumps(_redact(report.scope), ensure_ascii=False, sort_keys=True, indent=2)
    )
    body = [
        "<!doctype html>",
        '<html lang="en"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        '<meta http-equiv="Content-Security-Policy" ',
        "content=\"default-src 'none'; style-src 'unsafe-inline'; img-src data:\">",
        f"<title>{html.escape(report.organization_name)} configuration assessment</title>",
        f"<style>{HTML_STYLE}</style></head><body>",
        "<header>",
        '<p class="meta">BaselineGuard - Frozen assessment report</p>',
        f"<h1>{html.escape(report.organization_name)} - {html.escape(report.policy_name)}</h1>",
        f'<p class="meta">Report {report.report_id} - Policy revision '
        f"{report.policy_revision} - Cutoff {report.assessment_cutoff.isoformat()}</p>",
        "</header>",
        '<section aria-labelledby="summary-heading">',
        '<h2 id="summary-heading">Result summary</h2>',
        f'<div class="summary">{summary_rows}</div>',
        f"<p>Finding rows: {len(report.findings)}. Status is preserved; no pass rate is inferred "
        f"for incomplete checks. Completeness counts: <code>{completeness}</code>.</p></section>",
        '<section aria-labelledby="findings-heading">',
        '<h2 id="findings-heading">Control results</h2>',
        '<div style="overflow-x:auto"><table><thead><tr>',
        "<th>Asset</th><th>Control</th><th>Severity</th><th>Status</th><th>Reason</th>",
        "<th>Source</th><th>Expected</th><th>Actual</th><th>Evidence reference</th>",
        "<th>Remediation state</th><th>Procedure</th>",
        f"</tr></thead><tbody>{''.join(rows)}</tbody></table></div></section>",
        '<section aria-labelledby="scope-heading">',
        '<h2 id="scope-heading">Scope and integrity</h2>',
        f"<p>Policy digest <code>{report.policy_digest}</code>; engine digest "
        f"<code>{report.engine_digest}</code>.</p><pre>{scope_json}</pre></section>",
        omission_section,
        "</body></html>",
    ]
    page = "\n".join(body)
    return page.encode("utf-8")


def _artifact(
    report: ReportDocument,
    format_name: Literal["json", "html", "csv"],
    content: bytes,
) -> RenderedArtifact:
    media_type = {
        "json": "application/json",
        "html": "text/html; charset=utf-8",
        "csv": "text/csv; charset=utf-8",
    }[format_name]
    return RenderedArtifact(
        format=format_name,
        media_type=media_type,
        filename=f"baselineguard-{report.report_id}.{format_name}",
        byte_length=len(content),
        sha256=hashlib.sha256(content).hexdigest(),
        content=content,
    )


def render_report(
    report: ReportDocument,
    formats: tuple[Literal["json", "html", "csv"], ...] = ("json", "html", "csv"),
) -> tuple[RenderedArtifact, ...]:
    """Render requested formats from one immutable model; reject unsupported formats."""
    if not formats or len(formats) != len(set(formats)):
        raise ValueError("formats must be a non-empty tuple of unique supported formats")
    renderers = {"json": render_json, "html": render_html, "csv": render_csv}
    artifacts: list[RenderedArtifact] = []
    for format_name in formats:
        renderer = renderers.get(format_name)
        if renderer is None:
            raise ValueError("unsupported report format")
        artifacts.append(_artifact(report, format_name, renderer(report)))
    return tuple(artifacts)
