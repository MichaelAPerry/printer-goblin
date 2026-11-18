"""Assess every printer in an in-scope range and build one consolidated, paper-free report.

This module composes discovery (connect-only port sweep) with the paper-free identify
assessment. It has no way to submit a job to a device: it never imports the submission
modules and only calls the read-only workflow and probe functions.
"""

from __future__ import annotations

import csv
import hashlib
import io
import ipaddress
import json
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from functools import partial
from typing import Callable, Iterable, Optional

from . import discovery, net, report as base, safety, scope, workflow
from .identify import identify as probe_printer
from .payloads import notice

MAX_WORKERS = 4
_SECTIONS = ("devices", "other_hosts", "prevalence", "severity_totals", "recommendations")
_PRINTER_PORTS = {9100, 631, 515}  # print-protocol ports; 80/443 alone are not printer evidence
_COUNTED = ("high", "medium", "low", "info")
_SERIAL_MASK = "(redacted)"
_MAX_IPS_IN_SENTENCE = 8
UNCONFIRMED = "unconfirmed printer"

# Generic, vendor-neutral actions keyed by finding id. Each is a short imperative phrase;
# the report adds "on N of M printers (addresses)". `why` says what the finding means.
RECOMMENDATIONS: dict[str, tuple[str, str]] = {
    "UNAUTH_PRINT": (
        "Require authentication for printing, or restrict who can reach the print service",
        "IPP Validate-Job was approved without a login, so a real job would likely print. "
        "Nothing was printed during this assessment.",
    ),
    "RAW9100": (
        "Restrict raw port 9100 to the print server",
        "Raw port 9100 accepts jobs with no login. Allow it only from the print server or hosts that need it.",
    ),
    "TELNET": (
        "Turn off Telnet",
        "Telnet is an unencrypted management console.",
    ),
    "FTP": (
        "Turn off FTP unless it is needed",
        "FTP can accept print files or firmware uploads and sends data unencrypted.",
    ),
    "LPD": (
        "Turn off LPD (port 515) unless it is needed",
        "LPD is a legacy print protocol with no authentication.",
    ),
    "SNMP_PUBLIC": (
        "Change the default SNMP community, or turn SNMP off",
        "The default community 'public' exposed device information to anyone on the network.",
    ),
    "IPP_NO_AUTH": (
        "Turn on authentication for IPP printing",
        "All advertised IPP printer URIs list authentication as none.",
    ),
    "IPP_PLAIN": (
        "Prefer IPP over TLS and turn off plain IPP where clients support it",
        "Plain IPP answered without encryption, so printer details and jobs cross the network in the clear.",
    ),
    "HTTP_ADMIN": (
        "Serve the web admin page over HTTPS only",
        "Admin logins over plain HTTP can be read on the network.",
    ),
    "ALT_HTTP": (
        "Turn off the alternate HTTP port, or move admin access to HTTPS",
        "Admin logins on an unencrypted alternate port can be read on the network.",
    ),
    "LEGACY_TLS": (
        "Turn off TLS 1.0 and 1.1",
        "The printer completed a TLS 1.0 or 1.1 handshake, which are deprecated.",
    ),
    "HTTPS_ADMIN": (
        "Confirm the default admin password was changed",
        "A web admin page is served over HTTPS; default admin passwords are a common weakness.",
    ),
    "SMB": (
        "Turn off SMB file sharing unless it is needed",
        "SMB accepted a connection; scan-to-folder and sharing are rarely needed on every printer.",
    ),
    "SSH": (
        "Turn off SSH unless it is needed for management",
        "SSH accepted a connection.",
    ),
    "WSD": (
        "Turn off WSD discovery if clients do not use it",
        "WSD accepted a connection.",
    ),
    "ALT_HTTPS": (
        "Confirm the alternate HTTPS admin port is intended and the admin password was changed",
        "An alternate HTTPS port accepted a connection.",
    ),
    "FIRMWARE": (
        "Compare firmware with vendor security advisories and update where fixes exist",
        "Firmware versions were readable; check them against vendor advisories.",
    ),
}
_NO_RECOMMENDATION = {"IPP_AUTH_REQUIRED"}  # a good result, nothing to fix
_GENERIC_TITLES = {"FIRMWARE": "Firmware version reported"}  # per-device titles carry the version


def _risk_of(findings: Iterable[dict]) -> str:
    return max((f["severity"] for f in findings), key=base._SEVERITIES.index, default="none")


def _plural(count: int, noun: str = "printer") -> str:
    return f"{count} {noun}" + ("" if count == 1 else "s")


def _host_fields(host) -> tuple[str, list[int]]:
    if isinstance(host, dict):
        return str(host["ip"]), list(host.get("open_ports", []))
    return str(host.ip), list(host.open_ports)


def _assess_host(ip: str, open_ports: list[int], probe: Callable) -> dict:
    """Assess one host; every failure is recorded on the entry instead of raised."""
    entry = {"ip": ip, "model": None, "kind": None, "unconfirmed": False, "overall_risk": "unknown",
             "discovered_ports": open_ports, "findings": [], "evidence": {}, "error": None}
    serials: set = set()

    def capture(address):
        fingerprint = probe(address)
        serials.update(base._serials(fingerprint))
        return fingerprint

    try:
        scope.resolve_target(ip)
        evidence = workflow.identify(ip, probe=capture)
        findings = evidence.pop("findings")
    except Exception as exc:  # noqa: BLE001 - one bad host must not stop the fleet
        entry["error"] = base._redact(f"{type(exc).__name__}: {exc}", serials)
        return entry
    entry.update(
        model=base._redact(evidence["model"], serials), kind=evidence["kind"],
        unconfirmed=evidence["kind"] == "unknown",
        overall_risk=_risk_of(findings),
        findings=base._redact(findings, serials), evidence=base._redact(evidence, serials),
    )
    entry["ip"] = base._redact(ip, serials)
    return entry


def _prevalence(devices: list[dict], total: int) -> list[dict]:
    groups: dict[str, dict] = {}
    for device in devices:
        for finding in device["findings"]:
            group = groups.setdefault(finding["id"], {
                "id": finding["id"], "severity": finding["severity"],
                "title": _GENERIC_TITLES.get(finding["id"], finding["title"]),
                "ref": finding["ref"], "ips": []})
            if device["ip"] not in group["ips"]:
                group["ips"].append(device["ip"])
    rows = []
    for group in groups.values():
        count = len(group["ips"])
        rows.append({**group, "count": count, "of": total,
                     "label": f"{count} of {_plural(total)}"})
    return sorted(rows, key=lambda row: (-base._SEVERITIES.index(row["severity"]), -row["count"], row["id"]))


def _recommendations(prevalence: list[dict], devices: list[dict], total: int) -> list[dict]:
    recs = []
    for row in prevalence:
        if row["id"] in _NO_RECOMMENDATION:
            continue
        action, why = RECOMMENDATIONS.get(
            row["id"], (f"Review: {row['title']}", "See the remediation guide for this finding."))
        recs.append(_recommendation(row["id"], row["severity"], row["title"], row["ref"],
                                    row["ips"], total, action, why))
    unconfirmed = [d["ip"] for d in devices if d["unconfirmed"]]
    if unconfirmed:
        recs.append(_recommendation(
            "UNCONFIRMED", "info", "Unconfirmed printers", None, unconfirmed, total,
            "Confirm what these devices are",
            "They answered on printer ports but could not be identified as printers."))
    return sorted(recs, key=lambda rec: (-base._SEVERITIES.index(rec["severity"]), -rec["count"], rec["id"]))


def _recommendation(finding_id, severity, title, ref, ips, total, action, why) -> dict:
    count = len(ips)
    shown = ", ".join(ips[:_MAX_IPS_IN_SENTENCE])
    if count > _MAX_IPS_IN_SENTENCE:
        shown += f", +{count - _MAX_IPS_IN_SENTENCE} more"
    sentence = f"{action} on {count} of {_plural(total)} ({shown})"
    return {"id": finding_id, "severity": severity, "title": title, "ref": ref,
            "link": notice.guide_link(ref) if ref else None, "action": action,
            "sentence": sentence, "why": why, "ips": ips, "count": count, "of": total}


def _bottom_line(risk, assessed, unauth, errors) -> str:
    if not assessed and errors:
        return "No printer could be assessed; see the per-host errors."
    if not assessed:
        return "No hosts with open printer ports were found in this range."
    if unauth:
        text = (f"{unauth} of {_plural(assessed)} validated a print request without a login "
                "(nothing was printed).")
    elif risk not in ("none", "info"):
        where = "the one printer found" if assessed == 1 else f"at least one of {_plural(assessed)}"
        text = f"This assessment found {risk}-severity printer risks on {where}."
    else:
        text = "This assessment found no security risks above informational severity."
    return text + (f" {_plural(errors, 'host')} could not be assessed." if errors else "")


def _digest(result: dict) -> str:
    canonical = json.dumps({key: result[key] for key in _SECTIONS}, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def assess_fleet(cidr: str, *, ports: Iterable[int] = discovery.DEFAULT_PORTS, validate_job: bool = True,
                 workers: int = MAX_WORKERS, discover: Optional[Callable] = None,
                 identify: Optional[Callable] = None,
                 on_progress: Optional[Callable] = None) -> dict:
    """Discover printers in an in-scope range and assess each without printing.

    `discover(cidr, ports)` returns host dicts with `ip` and `open_ports`; `identify(ip)` returns an
    identify Fingerprint. Both default to the real read-only implementations. `on_progress(done,
    total, entry)` is called from the calling thread after each host.
    """
    addresses = scope.parse_scan_range(cidr)  # same private-only, /22-capped rules as discover
    ports = tuple(dict.fromkeys(ports))
    discover = discover or (lambda c, p: workflow.discover(c, p)["hosts"])
    probe = identify or partial(probe_printer, validate_job=validate_job, assess=True)
    found: dict[str, list[int]] = {}
    for host in discover(cidr, ports):
        ip, open_ports = _host_fields(host)
        found.setdefault(ip, open_ports)
    ordered = sorted(found, key=_ip_key)
    results: dict[str, dict] = {}
    with ThreadPoolExecutor(max_workers=max(1, min(int(workers), MAX_WORKERS))) as pool:
        futures = {pool.submit(_assess_host, ip, found[ip], probe): ip for ip in ordered}
        for done, future in enumerate(as_completed(futures), 1):
            entry = results[futures[future]] = future.result()
            if on_progress:
                on_progress(done, len(ordered), entry)
    everything = [results[ip] for ip in ordered]
    # A host with no print-protocol port and nothing identifying it as a printer (a router, a NAS)
    # is listed separately so it doesn't skew "N of M printers" or the recommendations.
    other_hosts = [{"ip": d["ip"], "open_ports": d["discovered_ports"]} for d in everything
                   if d["error"] is None and d["unconfirmed"]
                   and not _PRINTER_PORTS & set(d["evidence"].get("ports") or d["discovered_ports"])]
    others = {h["ip"] for h in other_hosts}
    devices = [d for d in everything if d["ip"] not in others]
    assessed = [d for d in devices if d["error"] is None]
    total = len(assessed)
    prevalence = _prevalence(assessed, total)
    totals = {level: sum(1 for d in assessed for f in d["findings"] if f["severity"] == level)
              for level in _COUNTED}
    risk = _risk_of(f for d in assessed for f in d["findings"]) if assessed else "none"
    unauth = next((row["count"] for row in prevalence if row["id"] == "UNAUTH_PRINT"), 0)
    anchor = ordered[0] if ordered else str(addresses[0])
    try:
        source = net.source_label(anchor)
    except OSError:
        source = "unknown"
    result = {
        "tool": {"name": "Printer Goblin", "version": base._version()},
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": source,
        "range": cidr,
        "ports": list(ports),
        "validate_job": bool(validate_job),
        "host_count": len(devices),
        "assessed_count": total,
        "error_count": len(devices) - total,
        "unconfirmed_count": sum(1 for d in assessed if d["unconfirmed"]),
        "overall_risk": risk,
        "bottom_line": _bottom_line(risk, total, unauth, len(devices) - total),
        "devices": devices,
        "other_hosts": other_hosts,
        "prevalence": prevalence,
        "severity_totals": totals,
        "recommendations": _recommendations(prevalence, assessed, total),
    }
    result["evidence_sha256"] = _digest(result)
    try:
        safety.PrintGovernor().audit("fleet-assess", range=cidr, hosts=len(devices), assessed=total,
                                     validate_job=bool(validate_job), sha256=result["evidence_sha256"])
    except OSError:
        pass  # an unwritable state dir must not lose the assessment itself
    return result


def _ip_key(value: str):
    try:
        address = ipaddress.ip_address(value.split("%")[0])
    except ValueError:
        return (0, 0)
    return (address.version, int(address))


def fleet_filename(result: dict, extension: str = "html") -> str:
    label = re.sub(r"[^a-zA-Z0-9._-]", "-", result["range"])
    timestamp = datetime.fromisoformat(result["generated_at"]).strftime("%Y%m%d-%H%M")
    return f"goblin-fleet-{label}-{timestamp}.{extension}"


def to_json(result: dict) -> str:
    return json.dumps(result, indent=2, sort_keys=True)


# -- rendering ---------------------------------------------------------------

_METHODOLOGY = (
    "Discovery is a TCP connect sweep of the range; it sends no application data. Each host that "
    "answered is then assessed with the same paper-free checks as a single-printer report: TCP "
    "reachability, IPP and HTTP queries, SNMP read with the public community, TLS handshake "
    "inspection, and server banners. No login credentials are tried, no settings are changed, no "
    "SNMP SET is issued, and nothing is sent to port 9100. "
    + "IPP Validate-Job prints nothing, and each check is recorded in the local audit log"
    + " (it can be skipped with --no-validate-job). Generating this report prints nothing on any device. "
    "Serial numbers are masked. Hosts that answered on printer ports but could not be identified as "
    "printers are kept and marked unconfirmed."
)

_FLEET_CSS = """
.stats { display: flex; flex-wrap: wrap; gap: .5rem 1.5rem; margin: .6rem 0 0; padding: 0; list-style: none; }
.rec-list li { margin: .5rem 0; }
.rec-list .why { color: #444; font-size: .9em; display: block; }
details { border: 1px solid #999; margin: .6rem 0; padding: .3rem .8rem; }
details[open] { padding-bottom: .8rem; }
summary { cursor: pointer; font-weight: 600; }
.flag { font-size: .8em; border: 1.5px dashed #111; padding: .05em .4em; margin-left: .4rem; }
.device-table td:nth-child(3), .device-table td:nth-child(4), .device-table td:nth-child(5),
.prev-table td:nth-child(1), .prev-table td:nth-child(5) { white-space: nowrap; }
@media print { details > * { display: block; } }
"""


def _badge(severity: str) -> str:
    level = severity if severity in base._BADGES else "info"
    return f'<span class="sev sev-{level}">{base._html(severity)}</span>'


def _counts(findings) -> dict:
    return {level: sum(1 for f in findings if f["severity"] == level) for level in _COUNTED}


def _top_finding(device) -> str:
    if device["error"]:
        return f"Error: {device['error']}"
    findings = device["findings"]
    return findings[0]["title"] if findings else "No findings"


def _sorted_devices(result):
    def key(device):
        rank = -base._SEVERITIES.index(device["overall_risk"]) if device["error"] is None else 1
        return (rank, _ip_key(device["ip"]))
    return sorted(result["devices"], key=key)


def _link(url_ref, label):
    url = base._guide_url(url_ref)
    return f'<a href="{base._html(url)}">{base._html(label)}</a>' if url else ""


def _rec_items(recs) -> str:
    items = []
    for rec in recs:
        link = _link(rec["ref"], "How to fix")
        items.append(
            f"<li>{_badge(rec['severity'])} <strong>{base._html(rec['sentence'])}</strong> "
            f"{link}<span class=\"why\">{base._html(rec['why'])}</span></li>")
    return "".join(items) or "<li>No configuration changes recommended.</li>"


def _device_row(device) -> str:
    counts = _counts(device["findings"])
    count_text = " / ".join(str(counts[level]) for level in _COUNTED) if device["error"] is None else "—"
    risk = _badge(device["overall_risk"]) if device["error"] is None else '<span class="sev sev-info">error</span>'
    kind = base._html(device["kind"] or "—")
    if device["unconfirmed"]:
        kind += f' <span class="flag">{UNCONFIRMED}</span>'
    cells = [base._html(device["ip"]), base._html(device["model"] or "Unknown"), kind, risk,
             count_text, base._html(_top_finding(device))]
    return "<tr><td>" + "</td><td>".join(cells) + "</td></tr>"


def _device_details(device) -> str:
    flag = f' <span class="flag">{UNCONFIRMED}</span>' if device["unconfirmed"] else ""
    risk = "error" if device["error"] else device["overall_risk"]
    head = (f"{base._html(device['ip'])} · {base._html(device['model'] or 'Unknown model')} · "
            f"{base._html(risk)}{flag}")
    if device["error"]:
        body = f"<p>Assessment failed: {base._html(device['error'])}</p>"
    else:
        body = (
            "<table><thead><tr><th>Severity</th><th>Finding</th><th>Basis</th><th>Detail</th>"
            f"<th>Remediation</th></tr></thead><tbody>{base._finding_rows(device['findings'])}</tbody></table>"
            f'<dl class="evidence">{base._evidence_rows(device["evidence"])}</dl>')
    return f"<details><summary>{head}</summary>{body}</details>"


def _prevalence_row(row) -> str:
    cells = [_badge(row["severity"]), base._html(row["title"]), base._html(row["label"]),
             base._html(", ".join(row["ips"])), _link(row["ref"], "How to fix") or "—"]
    return "<tr><td>" + "</td><td>".join(cells) + "</td></tr>"


def _summary_rows(result) -> list[tuple[str, str]]:
    totals = result["severity_totals"]
    return [
        ("Range", result["range"]),
        ("Printers found", f"{result['host_count']} ({result['assessed_count']} assessed, "
                           f"{result['unconfirmed_count']} unconfirmed, {result['error_count']} failed)"),
        ("Fleet risk", result["overall_risk"].capitalize()),
        ("Findings", ", ".join(f"{totals[level]} {level}" for level in _COUNTED)),
        ("Source vantage", result["source"]),
        ("Generated (UTC)", result["generated_at"]),
        ("Tool", f"{result['tool']['name']} {result['tool']['version']}"),
    ]


def _other_hosts_html(hosts) -> str:
    if not hosts:
        return ""
    items = "".join(f"<li>{base._html(h['ip'])} (TCP {base._html(', '.join(map(str, h['open_ports'])))})</li>"
                    for h in hosts)
    return ("<section><h2>Other hosts (not printers)</h2><p>These answered only on web ports and showed "
            f"no printer evidence, so they are left out of the findings above.</p><ul>{items}</ul></section>")


def _sections(result):
    return {key: result[key] for key in _SECTIONS}


def render_html(result: dict) -> str:
    """Standalone HTML fleet report; all printer-supplied text is escaped, no scripts."""
    summary = "".join(f"<dt>{base._html(label)}</dt><dd>{base._html(value)}</dd>"
                      for label, value in _summary_rows(result))
    devices = _sorted_devices(result)
    rows = "".join(_device_row(d) for d in devices) or '<tr><td colspan="6">No hosts found.</td></tr>'
    prevalence = "".join(_prevalence_row(r) for r in result["prevalence"]) \
        or '<tr><td colspan="5">No findings.</td></tr>'
    body = f"""<div class="summary"><dl>{summary}</dl><p class="bottom">{base._html(result['bottom_line'])}</p></div>
<section><h2>Top recommendations</h2><ol class="rec-list">{_rec_items(result['recommendations'][:10])}</ol></section>
<section><h2>Devices</h2>
<table class="device-table"><thead><tr><th>Address</th><th>Model</th><th>Kind</th><th>Risk</th>
<th>High / Med / Low / Info</th><th>Top finding</th></tr></thead><tbody>{rows}</tbody></table></section>
<section><h2>Finding prevalence</h2>
<table class="prev-table"><thead><tr><th>Severity</th><th>Finding</th><th>Prevalence</th><th>Addresses</th>
<th>Remediation</th></tr></thead><tbody>{prevalence}</tbody></table></section>
{_other_hosts_html(result.get("other_hosts") or [])}
<section><h2>Per-device details</h2>{"".join(_device_details(d) for d in devices) or "<p>No hosts found.</p>"}</section>
<section><h2>Methodology and safety</h2><p>{base._html(_METHODOLOGY)}</p></section>
<section class="appendix"><h2>Appendix · Evidence JSON</h2>
<p>SHA-256 <code>{base._html(result['evidence_sha256'])}</code></p>
<p>To check the digest, parse the JSON below, serialize it with sorted keys, ASCII escaping
and no separator whitespace, and hash the UTF-8 bytes.</p>
<pre id="evidence-json">{base._html(base._json(_sections(result)))}</pre></section>"""
    return base.document("Printer Goblin fleet assessment",
                         "Paper-free fleet exposure assessment · authorized testing only", body, _FLEET_CSS)


def render_markdown(result: dict) -> str:
    md = base._markdown
    lines = ["# Printer Goblin fleet assessment", ""]
    lines.extend(f"- **{label}** — {md(value)}" for label, value in _summary_rows(result))
    lines.extend(["", md(result["bottom_line"]), "", "## Top recommendations", ""])
    for index, rec in enumerate(result["recommendations"][:10], 1):
        line = f"{index}. **{md(rec['severity'].capitalize())}** · {md(rec['sentence'])}"
        url = base._guide_url(rec["ref"]).replace(" ", "%20").replace("<", "%3C").replace(">", "%3E")
        lines.append(line + (f" [How to fix]({url})" if url else ""))
    if not result["recommendations"]:
        lines.append("No configuration changes recommended.")
    lines.extend(["", "## Devices", "", "| Address | Model | Kind | Risk | H/M/L/I | Top finding |",
                  "|---|---|---|---|---|---|"])
    for device in _sorted_devices(result):
        counts = _counts(device["findings"])
        kind = md(device["kind"] or "—") + (f" ({UNCONFIRMED})" if device["unconfirmed"] else "")
        risk = "error" if device["error"] else device["overall_risk"]
        lines.append("| " + " | ".join([
            md(device["ip"]), md(device["model"] or "Unknown"), kind, md(risk),
            "/".join(str(counts[level]) for level in _COUNTED), md(_top_finding(device))]) + " |")
    lines.extend(["", "## Finding prevalence", ""])
    for row in result["prevalence"]:
        lines.append(f"- **{md(row['severity'].capitalize())}** · {md(row['title'])} — "
                     f"{md(row['label'])}: {md(', '.join(row['ips']))}")
    if not result["prevalence"]:
        lines.append("No findings.")
    if result.get("other_hosts"):
        lines.extend(["", "## Other hosts (not printers)", "",
                      "Answered only on web ports with no printer evidence; left out of the findings.", ""])
        lines.extend(f"- {md(h['ip'])} (TCP {md(', '.join(map(str, h['open_ports'])))})"
                     for h in result["other_hosts"])
    lines.extend(["", "## Per-device findings", ""])
    for device in _sorted_devices(result):
        lines.append(f"### {md(device['ip'])}")
        if device["error"]:
            lines.append(f"Assessment failed: {md(device['error'])}")
        for finding in device["findings"]:
            lines.append(f"- **{md(finding['severity'].capitalize())}** · {md(finding['title'])} "
                         f"({md(finding['basis'])}) — {md(finding['detail'])}")
        lines.append("")
    lines.extend(["## Methodology and safety", "", _METHODOLOGY, "",
                  f"Evidence SHA-256 `{result['evidence_sha256']}`", ""])
    return "\n".join(lines)


def _csv_cell(value):
    text = "" if value is None else str(value)
    return "'" + text if text.startswith(("=", "+", "-", "@", "\t", "\r")) else text


def render_csv(result: dict) -> str:
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\n")
    writer.writerow(["ip", "model", "kind", "risk", "high", "medium", "low", "info", "top_finding"])
    for device in _sorted_devices(result):
        counts = _counts(device["findings"])
        risk = "error" if device["error"] else device["overall_risk"]
        writer.writerow([_csv_cell(device["ip"]), _csv_cell(device["model"]), _csv_cell(device["kind"]),
                         risk, *(counts[level] for level in _COUNTED), _csv_cell(_top_finding(device))])
    return out.getvalue()


RENDERERS = {"html": render_html, "md": render_markdown, "json": to_json, "csv": render_csv}
