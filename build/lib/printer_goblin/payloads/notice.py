"""The content of the printed notice, independent of printer language."""

from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass, field
from typing import List, Optional

from ..findings import Finding, findings
from ..identify import Fingerprint

DEFAULT_GUIDE_URL = "https://michaelaperry.github.io/printer-goblin/"


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
        return [FACT_HEADING, *(self.device or ["(not identified)"]), *self.services,
                *(line for finding in self.findings
                  for line in (f"[{finding.severity.upper()}] {finding.title}", finding.detail))]


FACT_HEADING = "WHAT THE GOBLIN SAW"
_SERVICE_NAMES = {9100: "raw", 631: "IPP", 515: "LPD", 80: "HTTP", 443: "HTTPS"}


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
    return Notice(headline=HEADLINE, lines=lines + [""] + facts, url=guide_url,
                  footer=list(FOOTER),
                  device=device_lines(fingerprint) if fingerprint else [],
                  services=service_lines(fingerprint) if fingerprint else [],
                  findings=findings(fingerprint, source) if fingerprint else [])


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
