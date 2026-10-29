"""Dependency-free, deterministic PDF rendering of a frozen report (text layout, Helvetica)."""

from __future__ import annotations

import textwrap

from baselineguard_reporter.render import ReportDocument, _redact_text

LINES_PER_PAGE = 56
WIDTH = 96


def _escape(text: str) -> str:
    safe = text.encode("latin-1", "replace").decode("latin-1")
    return safe.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _lines(report: ReportDocument) -> list[str]:
    out = [
        "BaselineGuard assessment report",
        "",
        f"Organization: {report.organization_name}",
        f"Policy: {report.policy_name} (revision {report.policy_revision})",
        f"Policy digest: {report.policy_digest}",
        f"Assessment cutoff (UTC): {report.assessment_cutoff.isoformat()}",
        f"Scope: {', '.join(map(str, report.scope.get('assets', [])))}",
        "",
        "Completeness: " + ", ".join(f"{k}={v}" for k, v in sorted(report.completeness.items())),
    ]
    for note in report.omissions:
        out.append(f"Omission: {note}")
    out += ["", "Results", "-" * 60]
    for item in report.findings:
        head = (
            f"[{item.status.value}] {item.severity.upper()} {item.asset_name} - {item.control_key}"
        )
        out += textwrap.wrap(head, WIDTH, subsequent_indent="    ") or [head]
        out += textwrap.wrap(
            f"    expected: {item.expected}  actual: {item.actual}",
            WIDTH,
            subsequent_indent="      ",
        )
        if item.remediation_procedure:
            for line in item.remediation_procedure.splitlines():
                out += textwrap.wrap("    fix: " + line, WIDTH, subsequent_indent="         ")
        out.append("")
    return [_redact_text(line) for line in out]


def render_pdf(report: ReportDocument) -> bytes:
    lines = _lines(report)
    pages = [lines[i : i + LINES_PER_PAGE] for i in range(0, len(lines), LINES_PER_PAGE)] or [[]]
    objects: list[bytes] = []

    def add(body: bytes) -> int:
        objects.append(body)
        return len(objects)

    add(b"<< /Type /Catalog /Pages 2 0 R >>")
    add(b"")  # pages placeholder (object 2)
    font = add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>")
    kids: list[int] = []
    for page in pages:
        stream = ["BT", "/F1 9 Tf", "12 TL", "40 800 Td"]
        stream += [f"({_escape(line)}) Tj T*" for line in page]
        stream.append("ET")
        data = "\n".join(stream).encode("latin-1")
        content = add(b"<< /Length %d >>\nstream\n" % len(data) + data + b"\nendstream")
        kids.append(
            add(
                b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] "
                b"/Resources << /Font << /F1 %d 0 R >> >> /Contents %d 0 R >>" % (font, content)
            )
        )
    objects[1] = b"<< /Type /Pages /Count %d /Kids [%s] >>" % (
        len(kids),
        b" ".join(b"%d 0 R" % k for k in kids),
    )
    out: bytearray = bytearray(b"%PDF-1.4\n")
    offsets: list[int] = []
    for number, body in enumerate(objects, start=1):
        offsets.append(len(out))
        out += b"%d 0 obj\n" % number + body + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objects) + 1)
    for offset in offsets:
        out += b"%010d 00000 n \n" % offset
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (
        len(objects) + 1,
        xref,
    )
    return bytes(out)
