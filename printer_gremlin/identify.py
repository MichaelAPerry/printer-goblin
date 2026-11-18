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
    r"\b(?:TM-[TM]|Epson\s+TM|Star\s+TSP|mC-Print|Bixolon|SRP-|"
    r"Citizen\s+CT-S|XPrinter|POS-80|Rongta|receipt\b|thermal\b)", re.I
)
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


def _http_title(ip: str) -> Optional[str]:
    connection = http.client.HTTPConnection(ip, 80, timeout=2)
    try:
        connection.request("GET", "/")
        response = connection.getresponse()
        if not 200 <= response.status < 300:
            return None
        parser = _Title()
        parser.feed(response.read(64 * 1024).decode("utf-8", errors="replace"))
        return " ".join("".join(parser.parts).split()) or None
    except (OSError, http.client.HTTPException):
        return None
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
            if _THERMAL.search(value):
                result.kind = "thermal-escpos"
                result.reasons.append(f"{source} identifies a thermal printer: {value}")
            elif _OFFICE.search(value) and result.kind != "thermal-escpos":
                result.kind = "office"
                result.reasons.append(f"{source} identifies an office printer: {value}")

    for mime in result.ipp_attrs.get("document-format-supported", []):
        if isinstance(mime, str) and mime.lower() in _FORMATS:
            language = _FORMATS[mime.lower()]
            if language not in result.languages:
                result.languages.append(language)
                result.reasons.append(f"IPP advertises {mime}")
    if result.kind == "thermal-escpos":
        result.languages.insert(0, "escpos")
    elif result.languages:
        result.kind = "office"
    if not result.reasons:
        result.reasons.append("No printer model or supported document format recognized")


def identify(ip: str) -> Fingerprint:
    """Probe TCP ports and query IPP, SNMP, and HTTP without printing."""
    ip = str(scope.resolve_target(str(ip)))
    result = Fingerprint(ip)
    with ThreadPoolExecutor(max_workers=3) as pool:
        snmp_future = pool.submit(snmp.get_printer_values, ip)
        result.ports = [port for _, port, state in net.probe_many(
            ((ip, port) for port in DEFAULT_PORTS), 0.8
        ) if state == "open"]
        ipp_future = pool.submit(_ipp_attributes, ip) if 631 in result.ports else None
        http_future = pool.submit(_http_title, ip) if 80 in result.ports else None
        result.snmp_values = snmp_future.result()
        if ipp_future is not None:
            result.ipp_attrs, result.ipp_path = ipp_future.result()
        if http_future is not None:
            result.http_title = http_future.result()
    _add_evidence(result)
    return result
