"""Identify printer capabilities with read-only queries."""

from __future__ import annotations

import http.client
import re
import socket
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Optional

from . import net, safety, scope
from .discovery import DEFAULT_PORTS
from .protocols import ipp, snmp, tlsprobe

_ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]|\xff[\xfb-\xfe].")  # terminal escapes, telnet IAC

MGMT_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 445: "SMB", 5357: "WSD",
    8080: "alt-HTTP", 8443: "alt-HTTPS",
}

_THERMAL = re.compile(
    r"\b(?:Star\s+TSP|TSP\d|mC-Print|Bixolon|SRP-|"
    r"Citizen|XPrinter|POS-80|Rongta|receipt\b|thermal\b)", re.I
)
_EPSON_TM = re.compile(r"(?:\bEpson\s+TM-[A-Z0-9]+|^\s*TM-[TMUHJPLOS]\d+[A-Z0-9]*)\b", re.I)
_ESCPOS = re.compile(r"\bESC/POS\b", re.I)
_OFFICE = re.compile(r"\b(?:LaserJet|OfficeJet|LaserPrinter|imageRUNNER|WorkCentre|Bizhub)\b", re.I)
_FORMATS = {
    "application/postscript": "postscript",
    "application/vnd.hp-pcl": "pcl",
    "application/pdf": "pdf",
    "image/pwg-raster": "pwg-raster",
    "image/urf": "urf",
}


@dataclass
class Fingerprint:
    ip: str
    ports: list[int] = field(default_factory=list)
    ipp_attrs: dict[str, list[object]] = field(default_factory=dict)
    snmp_values: dict[str, str] = field(default_factory=dict)
    http_title: Optional[str] = None
    kind: str = "unknown"
    languages: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    ipp_path: Optional[str] = None
    ipp_ok: bool = False
    snmp_ok: bool = False
    snmp_languages: list[str] = field(default_factory=list)
    http_ok: bool = False
    firmware: Optional[str] = None
    validate_job_status: Optional[int] = None
    mgmt_ports: list[int] = field(default_factory=list)
    banners: dict[int, str] = field(default_factory=dict)
    tls: dict[int, tlsprobe.TLSResult] = field(default_factory=dict)

    @property
    def model(self) -> Optional[str]:
        return self._ipp_string("printer-make-and-model") or self.snmp_values.get("hrDeviceDescr")

    @property
    def serial(self) -> Optional[str]:
        return self._ipp_string("printer-serial-number") or self.snmp_values.get("prtGeneralSerialNumber")

    @property
    def media_default(self) -> Optional[str]:
        return self._ipp_string("media-default")

    def _ipp_string(self, name: str) -> Optional[str]:
        for value in self.ipp_attrs.get(name, []):
            if isinstance(value, bytes):
                decoded = value.decode("utf-8", errors="replace")
                value = decoded if decoded.isprintable() and "\ufffd" not in decoded else value.hex()
            if isinstance(value, str) and value.strip():
                return value
        return None


class _Title(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.in_title = False
        self.done = False
        self.parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list) -> None:
        if tag == "title" and not self.done:
            self.in_title = True

    def handle_endtag(self, tag: str) -> None:
        if tag == "title" and self.in_title:
            self.in_title = False
            self.done = True

    def handle_data(self, data: str) -> None:
        if self.in_title:
            self.parts.append(data)


def _http_title(ip: str) -> tuple[Optional[str], bool]:
    connection = http.client.HTTPConnection(ip, net.actual_port(ip, 80), timeout=2)
    responded = False
    try:
        connection.request("GET", "/")
        response = connection.getresponse()
        responded = True
        if not 200 <= response.status < 300:
            return None, responded
        parser = _Title()
        parser.feed(response.read(64 * 1024).decode("utf-8", errors="replace"))
        return " ".join("".join(parser.parts).split()) or None, responded
    except (OSError, http.client.HTTPException):
        return None, responded
    finally:
        connection.close()


def _ipp_attributes(ip: str) -> tuple[dict[str, list[object]], Optional[str]]:
    try:
        attrs, path = ipp.query_printer(ip, timeout=2)
        return {name: attrs[name] for name in ipp.REQUESTED_ATTRIBUTES if name in attrs}, path
    except (OSError, ValueError, http.client.HTTPException):
        return {}, None


def _add_evidence(result: Fingerprint) -> None:
    descriptions = {
        "IPP printer-make-and-model": result.ipp_attrs.get("printer-make-and-model", []),
        "SNMP sysDescr": [result.snmp_values.get("sysDescr", "")],
        "SNMP hrDeviceDescr": [result.snmp_values.get("hrDeviceDescr", "")],
    }
    for source, values in descriptions.items():
        for value in values:
            if not isinstance(value, str):
                continue
            epson_tm = _EPSON_TM.search(value)
            if epson_tm or _ESCPOS.search(value):
                if "escpos" not in result.languages:
                    result.languages.insert(0, "escpos")
                result.reasons.append(f"{source} indicates ESC/POS: {value}")
            if epson_tm or _THERMAL.search(value):
                result.kind = "thermal"
                result.reasons.append(f"{source} identifies a thermal printer: {value}")
            elif _OFFICE.search(value) and result.kind != "thermal":
                result.kind = "office"
                result.reasons.append(f"{source} identifies an office printer: {value}")

    for mime in result.ipp_attrs.get("document-format-supported", []):
        if isinstance(mime, str) and mime.lower() in _FORMATS:
            language = _FORMATS[mime.lower()]
            if language not in result.languages:
                result.languages.append(language)
                result.reasons.append(f"IPP advertises {mime}")
    for language in result.snmp_languages:
        # Older printers (e.g. HP JetDirect) list their languages in the Printer-MIB
        # even when their IPP endpoint can't be read.
        if language not in result.languages:
            result.languages.append(language)
            result.reasons.append(f"SNMP Printer-MIB lists interpreter {language}")
    extra_descriptions = [*result.ipp_attrs.get("printer-info", []), result.http_title]
    if "escpos" not in result.languages and any(
        isinstance(value, str) and _ESCPOS.search(value) for value in extra_descriptions
    ):
        result.languages.insert(0, "escpos")
        result.reasons.append("Device description mentions ESC/POS")
    if "escpos" in result.languages:
        result.kind = "thermal"
    elif result.kind != "thermal" and result.languages:
        result.kind = "office"
    if not result.reasons:
        result.reasons.append("No printer model or supported document format recognized")


def _passive_banner(ip: str, port: int) -> str:
    deadline = time.monotonic() + 2
    try:
        with socket.create_connection((ip, net.actual_port(ip, port)), timeout=2) as sock:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return ""
            sock.settimeout(remaining)
            data = sock.recv(512)
    except OSError:
        return ""
    text = _ANSI.sub("", data.decode("latin-1"))
    return "".join(ch for ch in text if 32 <= ord(ch) < 127).strip()[:120]


def _validate(result: Fingerprint) -> None:
    if not result.ipp_ok or 0x0004 not in result.ipp_attrs.get("operations-supported", []):
        return
    document_format = next(
        (value for value in result.ipp_attrs.get("document-format-supported", [])
         if isinstance(value, str) and value.strip()), None
    )
    if document_format is None:
        return
    try:
        result.validate_job_status = ipp.validate_job(
            result.ip, document_format, path=result.ipp_path or "/ipp/print", timeout=2
        )
    except (OSError, ValueError, http.client.HTTPException):
        pass
    safety.PrintGovernor().audit("validate-job", target=result.ip, status=result.validate_job_status)


def identify(ip: str, *, validate_job: bool = True, assess: bool = True) -> Fingerprint:
    """Probe TCP ports and query IPP, SNMP, and HTTP without printing."""
    ip = str(scope.resolve_target(str(ip)))
    result = Fingerprint(ip)
    with ThreadPoolExecutor(max_workers=6) as pool:
        snmp_future = pool.submit(snmp.probe_printer, ip)
        ports = (*DEFAULT_PORTS, *MGMT_PORTS) if assess else DEFAULT_PORTS
        states = net.probe_with_retry([(ip, port) for port in ports], 0.8)
        result.ports = [port for port in ports if states[(ip, port)] == "open"]
        result.mgmt_ports = [port for port in MGMT_PORTS if port in result.ports]
        ipp_future = pool.submit(_ipp_attributes, ip) if 631 in result.ports else None
        http_future = pool.submit(_http_title, ip) if 80 in result.ports else None
        banners = {port: pool.submit(_passive_banner, ip, port)
                   for port in (21, 23) if port in result.mgmt_ports}
        tls = {port: pool.submit(tlsprobe.probe, ip, port)
               for port in (443, 631, 8443) if assess and port in result.ports}
        if ipp_future is not None:
            result.ipp_attrs, result.ipp_path = ipp_future.result()
            result.ipp_ok = result.ipp_path is not None
            result.firmware = (result._ipp_string("printer-firmware-string-version")
                               or result._ipp_string("printer-firmware-version"))
            if assess and validate_job:
                _validate(result)
        if http_future is not None:
            result.http_title, result.http_ok = http_future.result()
        snmp_values, result.snmp_ok = snmp_future.result()
        result.snmp_values = {k: v for k, v in snmp_values.items() if isinstance(v, str)}
        result.snmp_languages = snmp.languages(snmp_values)
        result.banners = {port: banner for port, future in banners.items() if (banner := future.result())}
        result.tls = {port: future.result() for port, future in tls.items()}
    _add_evidence(result)
    return result
