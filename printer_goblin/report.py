"""Build and render a paper-free assessment for a client or IT team."""

from __future__ import annotations

import base64
import hashlib
import json
import re
from datetime import datetime, timezone
from html import escape
from importlib import metadata
from textwrap import indent
from urllib.parse import urlsplit

import printer_goblin

from . import net, safety, workflow
from .assets import ASSET_DIR
from .identify import identify
from .payloads import notice

_SECTIONS = ("evidence", "findings", "verify", "audit")
_SEVERITIES = ("none", "info", "low", "medium", "high", "critical")
_SERIAL_FIELDS = {"serial", "printer-serial-number", "prtgeneralserialnumber"}
HTML_CSP = ("default-src 'none'; img-src data:; style-src 'unsafe-inline'; "
            "script-src 'none'; base-uri 'none'; form-action 'none'")
_METHODOLOGY = (
    "The assessment checks TCP reachability, queries IPP and HTTP, reads SNMP using "
    "the public community, and inspects TLS handshakes and server banners. It tries no "
    "login credentials, changes no settings, issues no SNMP SET, and sends no application "
    "data to port 9100. IPP Validate-Job prints nothing. Generating this report prints "
    f"nothing. A separate authorized demo can print at most {safety.MAX_PRINTS_PER_RUN} "
    "notices per run. The timeline shows matching events from this machine's local audit log."
)

_REPORT_CSS = """
body { color: #111; background: #fff; font: 15px/1.5 system-ui, sans-serif;
       max-width: 64rem; margin: 2rem auto; padding: 0 1rem; }
header { display: flex; align-items: center; gap: 1rem; border-bottom: 3px solid #111;
         padding-bottom: .75rem; }
header h1 { margin: 0; font-size: 1.7rem; }
header p { margin: .1rem 0 0; color: #444; }
.summary { border: 2px solid #111; padding: 1rem 1.25rem; margin: 1.5rem 0; }
.summary dl { display: grid; grid-template-columns: max-content 1fr; gap: .25rem 1.25rem; margin: 0; }
.summary dd { margin: 0; overflow-wrap: anywhere; }
.bottom { font-size: 1.1rem; font-weight: 600; margin: .9rem 0 0; }
section { margin: 2rem 0; }
h2 { border-bottom: 1px solid #999; padding-bottom: .2rem; }
table { width: 100%; border-collapse: collapse; text-align: left; }
th, td { border-bottom: 1px solid #bbb; padding: .5rem .55rem; vertical-align: top; }
th { border-bottom: 2px solid #111; font-size: .85em; text-transform: uppercase; letter-spacing: .03em; }
td:nth-child(1), td:nth-child(3), td:nth-child(5) { white-space: nowrap; }
.sev { display: inline-block; min-width: 4.5em; text-align: center; font-size: .8em; font-weight: 700;
       text-transform: uppercase; padding: .1em .45em; border: 1.5px solid #111; border-radius: 3px; }
.sev-high { background: #111; color: #fff; }
.sev-medium { background: repeating-linear-gradient(45deg, #fff 0 3px, #ddd 3px 6px); }
.sev-low, .sev-info { color: #444; border-color: #777; }
.evidence dt { font-weight: 700; margin-top: .6rem; }
.evidence dd { margin: .1rem 0 0 1rem; overflow-wrap: anywhere; }
.kv { margin: 0; padding: 0; list-style: none; }
.kv li { margin: 0; }
.kv .kv { padding-left: 1.1rem; }
.kv b { font-weight: 600; }
dt { font-weight: bold; }
pre { white-space: pre-wrap; overflow-wrap: anywhere; font-size: .8em; margin: 0; }
code { overflow-wrap: anywhere; }
a { color: inherit; text-decoration: underline; }
@media print {
  body { margin: 0; padding: 0; font-size: 10pt; max-width: none; }
  section.appendix, section.timeline { break-before: page; }
  h2, dt { break-after: avoid; }
  tr { break-inside: avoid; }
  thead { display: table-header-group; }
  .sev-high { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
}
"""


def _version():
    version = getattr(printer_goblin, "__version__", None)
    if version:
        return version
    try:
        return metadata.version("printer-goblin")
    except metadata.PackageNotFoundError:
        return "unknown"


def _serials(fp):
    values = set()
    for raw in [*fp.ipp_attrs.get("printer-serial-number", []),
                fp.snmp_values.get("prtGeneralSerialNumber")]:
        if isinstance(raw, bytes):
            values.add(raw.hex())
            raw = raw.decode("utf-8", errors="replace")
        if isinstance(raw, str):
            values.add(" ".join(raw.split()).casefold())
    return values - {""}


def _redact(value, serials, *, redact_keys=False):
    if isinstance(value, str):
        normalized = " ".join(value.split()).casefold()
        return "(redacted)" if any(serial in normalized for serial in serials) else value
    if isinstance(value, list):
        return [_redact(item, serials, redact_keys=redact_keys) for item in value]
    if isinstance(value, dict):
        return {
            (_redact(key, serials) if redact_keys and key.casefold() not in _SERIAL_FIELDS else key): (
                "(redacted)" if key.casefold() in _SERIAL_FIELDS and item
                else _redact(item, serials, redact_keys=redact_keys or key == "ipp_attrs")
            )
            for key, item in value.items()
        }
    return value


def _audit_entries(target, ip):
    entries = []
    try:
        audit = (safety.state_dir() / "audit.log").open(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        return entries
    with audit:
        for line in audit:
            try:
                entry = json.loads(line)
            except ValueError:
                continue
            if isinstance(entry, dict) and (
                entry.get("ip") == ip
                or (not entry.get("ip") and entry.get("target") in (target, ip))
            ):
                entries.append(entry)
    return entries


def _sections(report):
    return {key: report[key] for key in _SECTIONS}


def _json(value):
    return json.dumps(value, indent=2, sort_keys=True)


def build_report(target, *, baseline_path=None, include_audit=True, probe=identify) -> dict:
    """Collect fresh evidence and optionally compare all endpoints in a saved baseline."""
    serials = set()

    def capture(address):
        fp = probe(address)
        serials.update(_serials(fp))
        return fp

    evidence = workflow.identify(target, probe=capture)
    ip = evidence["ip"]
    findings = evidence.pop("findings")
    verification = workflow.verify(baseline_path) if baseline_path is not None else None
    audit = _audit_entries(target, ip) if include_audit else None
    risk = max((finding["severity"] for finding in findings), key=_SEVERITIES.index, default="none")
    if any(finding["id"] == "UNAUTH_PRINT" for finding in findings):
        bottom_line = "From this network, the printer validated a print request without a login."
    elif risk not in ("none", "info"):
        bottom_line = f"This assessment found {risk}-severity printer risks from this network."
    elif evidence["ports"]:
        bottom_line = "This assessment found no security risks above informational severity."
    else:
        bottom_line = "No assessed TCP ports were open from this network."
    report = {
        "tool": {"name": "Printer Goblin", "version": _version()},
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target": _redact(ip, serials),
        "model": _redact(evidence["model"], serials),
        "source": _redact(net.source_label(ip), serials),
        "overall_risk": risk,
        "bottom_line": bottom_line,
    }
    for key, value in zip(_SECTIONS, (evidence, findings, verification, audit)):
        report[key] = _redact(value, serials)
    canonical = json.dumps(_sections(report), sort_keys=True, separators=(",", ":"))
    report["evidence_sha256"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return report


def report_filename(report, extension="html"):
    address = re.sub(r"[^a-zA-Z0-9._-]", "-", report["target"])
    timestamp = datetime.fromisoformat(report["generated_at"]).strftime("%Y%m%d-%H%M")
    return f"goblin-report-{address}-{timestamp}.{extension}"


def _guide_url(ref):
    if not ref or ref == "(redacted)":
        return ""
    guide_link = getattr(notice, "guide_link", None)
    url = guide_link(ref) if guide_link else notice.DEFAULT_GUIDE_URL + "findings/#" + ref
    try:
        return url if urlsplit(url).scheme in ("http", "https") else ""
    except ValueError:
        return ""


def _html(value):
    return escape(str(value), quote=True)


_BADGES = ("high", "medium", "low", "info")


def _readable(value):
    """Human-readable evidence; the exact JSON stays in the appendix."""
    if isinstance(value, dict):
        items = "".join(f"<li><b>{_html(key)}:</b> {_readable(item)}</li>" for key, item in value.items())
        return f'<ul class="kv">{items}</ul>'
    if isinstance(value, list):
        if all(not isinstance(item, (dict, list)) for item in value):
            return _html(", ".join(str(item) for item in value))
        return "".join(_readable(item) for item in value)
    return _html(value)


def _pre(value):
    return "<pre>" + _html(_json(value)) + "</pre>"


def _summary(report):
    rows = [
        ("Target", report["target"]),
        ("Model", report["model"] or "Unknown"),
        ("Overall risk", report["overall_risk"].capitalize()),
        ("Source vantage", report["source"]),
        ("Generated (UTC)", report["generated_at"]),
        ("Tool", f"{report['tool']['name']} {report['tool']['version']}"),
    ]
    if report["verify"] is not None:
        rows.append(("Verification verdict", report["verify"].get("verdict", "Unavailable")))
    return rows


def _finding_rows(findings):
    rows = []
    for finding in findings:
        severity = finding["severity"] if finding["severity"] in _BADGES else "info"
        cells = [f'<span class="sev sev-{severity}">{_html(finding["severity"])}</span>',
                 *(_html(finding[key]) for key in ("title", "basis", "detail"))]
        url = _guide_url(finding["ref"])
        cells.append(f'<a href="{_html(url)}">How to fix</a>' if url else "—")
        rows.append("<tr><td>" + "</td><td>".join(cells) + "</td></tr>")
    return "".join(rows) or '<tr><td colspan="5">No findings.</td></tr>'


def _evidence_rows(evidence):
    labels = (
        ("ports", "Open TCP ports"), ("services", "Services"),
        ("banners", "Management banners"), ("tls", "TLS results"),
        ("ipp_attrs", "IPP attributes"), ("validate_job_status", "IPP Validate-Job status"),
        ("snmp_values", "SNMP values"), ("http_title", "HTTP title"), ("firmware", "Firmware"),
    )
    rows = []
    for key, label in labels:
        value = evidence.get(key)
        if key == "validate_job_status" and type(value) is int:
            value = f"0x{value:04x}"
        if value in (None, "", [], {}):
            display = "No data recorded"
        else:
            display = _readable(value)
        rows.append(f"<dt>{label}</dt><dd>{display}</dd>")
    return "".join(rows)


def _verification_html(verification):
    if verification is None:
        return "<p>No baseline supplied.</p>"
    rows = []
    for ip, ports in verification["results"].items():
        for port, result in ports.items():
            cells = [ip, port, *(result[key] for key in ("policy", "before", "after", "classification"))]
            rows.append("<tr><td>" + "</td><td>".join(map(_html, cells)) + "</td></tr>")
    return (
        f"<p><strong>{_html(verification['verdict'])}</strong> "
        f"{_html(verification['explanation'])}</p><p>{_html(verification['note'])}</p>"
        "<table><thead><tr><th>Address</th><th>Port</th><th>Expected</th><th>Before</th>"
        "<th>Now</th><th>Result</th></tr></thead><tbody>" + "".join(rows) + "</tbody></table>"
    )


def _audit_html(audit):
    if audit is None:
        return "<p>Audit log excluded.</p>"
    if not audit:
        return "<p>No matching audit entries.</p>"
    rows = []
    for entry in audit:
        try:
            timestamp = datetime.fromtimestamp(entry["ts"], timezone.utc).isoformat(timespec="seconds")
        except (KeyError, TypeError, ValueError, OSError, OverflowError):
            timestamp = "Time unavailable"
        detail = {key: value for key, value in entry.items() if key not in ("ts", "event")}
        rows.append(f"<li><strong>{_html(entry.get('event', 'Event'))}</strong> "
                    f"{_html(timestamp)}{_pre(detail)}</li>")
    return "<ol>" + "".join(rows) + "</ol>"


def render_html(report) -> str:
    """Render a standalone HTML document with an extractable JSON appendix."""
    mascot = base64.b64encode((ASSET_DIR / "goblin_256.png").read_bytes()).decode("ascii")
    summary = "".join(f"<dt>{_html(label)}</dt><dd>{_html(value)}</dd>"
                      for label, value in _summary(report))
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="{_html(HTML_CSP)}">
<title>Printer Goblin assessment report</title>
<style>{_REPORT_CSS}</style>
</head>
<body>
<header><img src="data:image/png;base64,{mascot}" width="72" height="72" alt="Printer Goblin mascot">
<div><h1>Printer Goblin assessment report</h1>
<p>Paper-free printer exposure assessment · authorized testing only</p></div></header>
<div class="summary"><dl>{summary}</dl><p class="bottom">{_html(report['bottom_line'])}</p></div>
<section><h2>Findings</h2>
<table><thead><tr><th>Severity</th><th>Finding</th><th>Basis</th><th>Detail</th><th>Remediation</th></tr></thead>
<tbody>{_finding_rows(report['findings'])}</tbody></table></section>
<section><h2>Evidence</h2><dl class="evidence">{_evidence_rows(report['evidence'])}</dl></section>
<section><h2>Isolation verification</h2>{_verification_html(report['verify'])}</section>
<section class="timeline"><h2>Activity timeline</h2>{_audit_html(report['audit'])}</section>
<section><h2>Methodology and safety</h2><p>{_html(_METHODOLOGY)}</p></section>
<section class="appendix"><h2>Appendix · Evidence JSON</h2>
<p>SHA-256 <code>{_html(report['evidence_sha256'])}</code></p>
<p>To check the digest, parse the JSON below, serialize it with sorted keys, ASCII escaping
and no separator whitespace, and hash the UTF-8 bytes.</p>
<pre id="evidence-json">{_html(_json(_sections(report)))}</pre></section>
</body>
</html>
"""


def _markdown(value):
    line = " ".join(str(value).split())
    line = line.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return re.sub(r"([\\`*_\[\]|~])", r"\\\1", line)


def render_markdown(report) -> str:
    """Render a lightweight, ticket-friendly assessment."""
    lines = ["# Printer Goblin assessment report", ""]
    lines.extend(f"- **{label}** — {_markdown(value)}" for label, value in _summary(report))
    lines.extend(["", _markdown(report["bottom_line"]), "", "## Findings", ""])
    for finding in report["findings"]:
        label = f"{finding['severity'].capitalize()} · {finding['title']} ({finding['basis']})"
        line = f"- **{_markdown(label)}** — {_markdown(finding['detail'])}"
        url = _guide_url(finding["ref"])
        if url:
            url = url.replace(" ", "%20").replace("<", "%3C").replace(">", "%3E")
            line += f" [How to fix]({url})"
        lines.append(line)
    if not report["findings"]:
        lines.append("No findings.")
    for title, key, missing in (
        ("Evidence", "evidence", "No evidence recorded."),
        ("Isolation verification", "verify", "No baseline supplied."),
        ("Activity timeline", "audit", "Audit log excluded."),
    ):
        value = report[key]
        if key == "audit" and value == []:
            display = "No matching audit entries."
        else:
            display = indent(_json(value), "    ") if value is not None else missing
        lines.extend(["", f"## {title}", "", display])
    lines.extend(["", "## Methodology and safety", "", _METHODOLOGY, "",
                  f"Evidence SHA-256 `{report['evidence_sha256']}`", ""])
    return "\n".join(lines)
