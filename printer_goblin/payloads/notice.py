"""The content of the printed notice, independent of printer language."""

from __future__ import annotations

import datetime as _dt
import re
from dataclasses import dataclass, field
from typing import List, Optional

from ..findings import Finding, findings
from ..identify import MGMT_PORTS, Fingerprint

DEFAULT_GUIDE_URL = "https://michaelaperry.github.io/printer-goblin/"
FINDINGS_PAGE = "findings/"
_REF = re.compile(r"[a-z0-9-]+")


def guide_link(ref: str | None, guide_url: str = DEFAULT_GUIDE_URL) -> str:
    """Deep link to a finding's fix on the default guide; other guides are returned unchanged."""
    if guide_url != DEFAULT_GUIDE_URL or not isinstance(ref, str) or not _REF.fullmatch(ref):
        return guide_url
    return DEFAULT_GUIDE_URL + FINDINGS_PAGE + "#" + ref


@dataclass
class Notice:
    headline: str
    lines: List[str]
    url: str
    footer: List[str] = field(default_factory=list)
    device: List[str] = field(default_factory=list)
    services: List[str] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    mascot: bool = True

    def fact_lines(self) -> list[str]:
        # Firmware already appears in the serial-redacted device section.
        report = [item for item in self.findings if item.id != "FIRMWARE"][:6]
        return [FACT_HEADING, *(self.device or ["(not identified)"]), *self.services,
                *(line for finding in report
                  for line in (f"[{finding.severity.upper()}] {finding.title}"[:84], finding.detail[:84]))]


FACT_HEADING = "WHAT THE GOBLIN SAW"
_SERVICE_NAMES = {9100: "raw", 631: "IPP", 515: "LPD", 80: "HTTP", 443: "HTTPS", **MGMT_PORTS}


def service_lines(fp: Fingerprint) -> list[str]:
    return [f"{port} {_SERVICE_NAMES.get(port, 'TCP')}  OPEN" for port in fp.ports]


def device_lines(fp: Fingerprint) -> list[str]:
    # Report only display attributes. Some devices also embed the serial in the model.
    serials = [*fp.ipp_attrs.get("printer-serial-number", []),
               fp.snmp_values.get("prtGeneralSerialNumber")]
    private_values = set()
    for value in serials:
        if isinstance(value, bytes):
            private_values.add(value.hex())
            value = value.decode("utf-8", errors="replace")
        if isinstance(value, str) and value.strip():
            private_values.add(" ".join(value.split()).casefold())
    result = []
    for label, value in (("Model", fp.model), ("Firmware", fp.firmware)):
        if value:
            value = " ".join(value.split())
            if any(serial in value.casefold() for serial in private_values):
                value = "(redacted)"
            result.append(f"{label}: {value[:64]}")
    kind = {"office": "office printer", "thermal": "thermal receipt printer"}
    return [*result, f"Type: {kind.get(fp.kind, 'unknown')}"]


def build_notice(target: str, port: int, protocol: str, source: str,
                 guide_url: str = DEFAULT_GUIDE_URL, note: str = "",
                 when: Optional[_dt.datetime] = None, *,
                 fingerprint: Optional[Fingerprint] = None) -> Notice:
    when = when or _dt.datetime.now().astimezone()
    lines = list(NOTICE_BODY)
    facts = [
        f"Printer:  {target}:{port} ({protocol})",
        f"Reached from: {source}",
        f"Time: {when.strftime('%Y-%m-%d %H:%M %Z')}",
    ]
    if note:
        facts.append(f"Assessor: {note[:60]}")
    services = service_lines(fingerprint) if fingerprint else []
    if len(services) > 5:
        services = [*services[:4], f"{len(services) - 4} more TCP ports open"]
    report = findings(fingerprint, source) if fingerprint else []
    url = guide_link(report[0].ref, guide_url) if report else guide_url
    return Notice(headline=HEADLINE, lines=lines + [""] + facts, url=url,
                  footer=list(FOOTER),
                  device=device_lines(fingerprint) if fingerprint else [],
                  services=services, findings=report)


# Wording is kept short so it fits a 32-column receipt.
HEADLINE = "YOU'VE BEEN GOBBED!"
# Drafted by the local wording model (qwen3.5:9b); line 4 corrected for
# accuracy (printers usually keep a job-log entry, so "nothing saved" is untrue).
NOTICE_BODY: List[str] = [
    "A goblin just grabbed a page here!",
    "It came from a network that shouldn't reach us.",
    "This was an authorized security test, not a hack.",
    "No settings were changed and nothing was taken.",
    "Please hand this sheet to your IT or Security team.",
    "We are checking our printer protection right now.",
]
FOOTER: List[str] = [
    "Scan the QR code to learn how we will fix it.",
    "-- Printer Goblin",
]
