"""Translate observed printer probe results into fact-sheet findings."""

from dataclasses import dataclass

from .identify import Fingerprint


@dataclass(frozen=True)
class Finding:
    id: str
    severity: str
    title: str
    detail: str


def findings(fp: Fingerprint, source_ip: str) -> list[Finding]:
    """Report observations from the probe vantage identified by source_ip."""
    observations = (
        (9100 in fp.ports, Finding("RAW9100", "high", "Raw print port 9100 reachable",
                                 "Accepts print data with no login (AppSocket/JetDirect).")),
        (fp.ipp_ok and not fp.ipp_tls, Finding("IPP_PLAIN", "medium", "IPP answers without TLS",
                                             "Printer details are readable by anyone on this network.")),
        (515 in fp.ports, Finding("LPD", "medium", "LPD port 515 reachable",
                                 "Legacy print protocol; disable it if unused.")),
        (fp.snmp_ok, Finding("SNMP_PUBLIC", "medium", "SNMP answers community 'public'",
                             "Device info readable with the default community string.")),
        (fp.http_ok, Finding("HTTP_ADMIN", "medium", "Web admin on plain HTTP",
                             "Admin logins could cross the network unencrypted.")),
        (443 in fp.ports, Finding("HTTPS_ADMIN", "info", "Web admin on HTTPS",
                                 "Make sure the default admin password was changed.")),
    )
    return [finding for observed, finding in observations if observed]
