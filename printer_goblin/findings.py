"""Translate observed printer probe results into fact-sheet findings."""

from dataclasses import dataclass
from typing import Optional

from .advisories import vendor_advisory_url
from .identify import Fingerprint


@dataclass(frozen=True)
class Finding:
    id: str
    severity: str
    title: str
    detail: str
    basis: str
    ref: Optional[str] = None

    def __post_init__(self) -> None:
        if self.ref is None:
            ref = "raw-9100" if self.id == "RAW9100" else self.id.lower().replace("_", "-")
            object.__setattr__(self, "ref", ref)


_MANAGEMENT = {
    21: Finding("FTP", "medium", "FTP port open",
                "Likely: accepts print files and firmware uploads; disable if unused.", "inferred"),
    22: Finding("SSH", "info", "SSH port open", "TCP port 22 accepted a connection.", "observed"),
    23: Finding("TELNET", "high", "Telnet port open",
                "Likely: unencrypted management console; disable it.", "inferred"),
    445: Finding("SMB", "low", "SMB port open", "TCP port 445 accepted a connection.", "observed"),
    5357: Finding("WSD", "info", "WSD port open", "TCP port 5357 accepted a connection.", "observed"),
    8080: Finding("ALT_HTTP", "medium", "Alternate HTTP port open",
                  "Likely: admin logins cross the network unencrypted.", "inferred"),
    8443: Finding("ALT_HTTPS", "info", "Alternate HTTPS port open",
                  "TCP port 8443 accepted a connection.", "observed"),
}
_SEVERITY = {"high": 0, "medium": 1, "low": 2, "info": 3}


def _ipp_findings(fp: Fingerprint) -> list[Finding]:
    report = []
    status = fp.validate_job_status
    if status is not None and 0 <= status <= 0x00FF:
        report.append(Finding("UNAUTH_PRINT", "high", "Printer approved a print job without login",
                              "Validate-Job passed with no login (nothing printed); a real job would likely print.",
                              "observed"))
    elif status in (0x0401, 0x0402, 0x0403):
        report.append(Finding("IPP_AUTH_REQUIRED", "info", "IPP printing requires authorization",
                              "Validate-Job returned an IPP authorization error.", "observed"))

    uris = fp.ipp_attrs.get("printer-uri-supported", [])
    auth = fp.ipp_attrs.get("uri-authentication-supported", [])
    security = fp.ipp_attrs.get("uri-security-supported", [])
    endpoints = [(uri, auth[index] if index < len(auth) else None,
                  security[index] if index < len(security) else None)
                 for index, uri in enumerate(uris) if isinstance(uri, str) and uri.strip()]
    if (not report or report[0].id != "UNAUTH_PRINT") and endpoints \
            and len(endpoints) == len(uris) and all(a == "none" for _, a, _ in endpoints):
        report.append(Finding("IPP_NO_AUTH", "medium", "IPP printing allows anonymous jobs (advertised)",
                              "All advertised printer URIs list authentication as none.", "observed"))

    tls_advertised = any(uri.lower().startswith("ipps://") or sec == "tls"
                         for uri, _, sec in endpoints)
    tls = fp.tls.get(631)
    detail = "Printer details were readable without a login."
    if not tls_advertised and endpoints:
        detail += " No TLS advertised for printer URIs."
    if tls_advertised:
        detail += " TLS is advertised for at least one printer URI."
    if tls and (tls.version or tls.legacy == "accepted"):
        detail += " TCP 631 also negotiated TLS."
    if fp.ipp_ok:
        report.append(Finding("IPP_PLAIN", "medium", "IPP answers without TLS", detail, "observed"))
    return report


def findings(fp: Fingerprint, source_ip: str) -> list[Finding]:
    """Report observations from the probe vantage identified by source_ip."""
    observations = (
        (9100 in fp.ports, Finding("RAW9100", "high", "Raw print port 9100 open",
                                 "Likely: accepts print jobs with no login (not tested).", "inferred")),
        (515 in fp.ports, Finding("LPD", "medium", "LPD port 515 open",
                                 "Likely: legacy protocol; disable if unused.", "inferred")),
        (fp.snmp_ok, Finding("SNMP_PUBLIC", "medium", "SNMP answers community 'public'",
                             "Device info was readable with the default community.", "observed")),
        (fp.http_ok, Finding("HTTP_ADMIN", "medium", "Web admin served over HTTP",
                             "Likely: admin logins cross the network unencrypted.", "inferred")),
        (443 in fp.ports, Finding("HTTPS_ADMIN", "info", "Web admin on HTTPS",
                                 "Check that the default admin password was changed.", "observed")),
    )
    report = [*_ipp_findings(fp), *(finding for observed, finding in observations if observed)]
    report.extend(finding for port, finding in _MANAGEMENT.items() if port in fp.ports)
    legacy = {port: tls for port, tls in fp.tls.items() if tls.legacy == "accepted"}
    if legacy:
        ports = ", ".join(str(port) for port in legacy)
        only = [str(port) for port, tls in legacy.items() if tls.modern is False]
        detail = f"Legacy TLS handshake succeeded on TCP {ports}."
        if only:
            detail += f" No TLS 1.2+ handshake succeeded on TCP {', '.join(only)}."
        report.append(Finding("LEGACY_TLS", "medium", "Printer accepts TLS 1.0/1.1", detail, "observed"))
    if fp.firmware:
        detail = "Compare against the vendor's security advisories."
        url = vendor_advisory_url(fp.model)
        if url:
            detail += f" {url}"
        report.append(Finding("FIRMWARE", "info", f"Firmware {fp.firmware} reported", detail, "observed"))
    return sorted(report, key=lambda finding: _SEVERITY[finding.severity])
