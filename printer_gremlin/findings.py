"""Translate observed printer probe results into fact-sheet findings."""

from dataclasses import dataclass

from .identify import Fingerprint


@dataclass(frozen=True)
class Finding:
    id: str
    severity: str
    title: str
    detail: str
    basis: str


def findings(fp: Fingerprint, source_ip: str) -> list[Finding]:
    """Report observations from the probe vantage identified by source_ip."""
    observations = (
        (9100 in fp.ports, Finding("RAW9100", "high", "Raw print port 9100 open",
                                 "Likely: accepts print jobs with no login (not tested).", "inferred")),
        (fp.ipp_ok, Finding("IPP_PLAIN", "medium", "IPP answers without TLS",
                            "Printer details were readable without a login.", "observed")),
        (515 in fp.ports, Finding("LPD", "medium", "LPD port 515 open",
                                 "Likely: legacy protocol; disable if unused.", "inferred")),
        (fp.snmp_ok, Finding("SNMP_PUBLIC", "medium", "SNMP answers community 'public'",
                             "Device info was readable with the default community.", "observed")),
        (fp.http_ok, Finding("HTTP_ADMIN", "medium", "Web admin served over HTTP",
                             "Likely: admin logins cross the network unencrypted.", "inferred")),
        (443 in fp.ports, Finding("HTTPS_ADMIN", "info", "Web admin on HTTPS",
                                 "Check that the default admin password was changed.", "observed")),
    )
    return [finding for observed, finding in observations if observed]
