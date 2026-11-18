"""Identify printer capabilities with read-only queries."""

from __future__ import annotations

import http.client
import re
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Optional

from . import net, scope
from .discovery import DEFAULT_PORTS
from .protocols import ipp, snmp

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
    http_ok: bool = False
    firmware: Optional[str] = None

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


def identify(ip: str) -> Fingerprint:
    """Probe TCP ports and query IPP, SNMP, and HTTP without printing."""
    ip = str(scope.resolve_target(str(ip)))
    result = Fingerprint(ip)
    with ThreadPoolExecutor(max_workers=3) as pool:
        snmp_future = pool.submit(snmp.probe_printer, ip)
        states = net.probe_with_retry([(ip, port) for port in DEFAULT_PORTS], 0.8)
        result.ports = [port for port in DEFAULT_PORTS if states[(ip, port)] == "open"]
        ipp_future = pool.submit(_ipp_attributes, ip) if 631 in result.ports else None
        http_future = pool.submit(_http_title, ip) if 80 in result.ports else None
        result.snmp_values, result.snmp_ok = snmp_future.result()
        if ipp_future is not None:
            result.ipp_attrs, result.ipp_path = ipp_future.result()
            result.ipp_ok = result.ipp_path is not None
            result.firmware = (result._ipp_string("printer-firmware-string-version")
                               or result._ipp_string("printer-firmware-version"))
        if http_future is not None:
            result.http_title, result.http_ok = http_future.result()
    _add_evidence(result)
    return result
