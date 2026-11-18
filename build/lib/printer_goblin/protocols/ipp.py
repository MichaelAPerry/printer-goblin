"""Minimal IPP/1.1 client and binary attribute codec."""

from __future__ import annotations

import http.client
import struct
from typing import Optional

from ..scope import resolve_target

REQUESTED_ATTRIBUTES = (
    "printer-make-and-model", "printer-info", "document-format-supported", "printer-state",
    "printer-firmware-string-version", "printer-firmware-version", "printer-serial-number",
    "media-default",
)
_TEXT_TAGS = {0x41, 0x42, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49}
_MAX_RESPONSE = 1024 * 1024


def encode_request(operation: int, printer_uri: str, *, request_id: int = 1,
                   requested_attributes: tuple[str, ...] = (),
                   document_format: Optional[str] = None,
                   job_name: Optional[str] = None, data: bytes = b"",
                   job_id: Optional[int] = None) -> bytes:
    """Encode one operation group, optionally followed by a document."""
    result = bytearray(struct.pack(">BBHI", 1, 1, operation, request_id) + b"\x01")

    def attr(tag: int, name: str, value: str | int) -> None:
        key = name.encode("ascii")
        raw = struct.pack(">i", value) if isinstance(value, int) else value.encode("utf-8")
        result.extend(bytes([tag]) + struct.pack(">H", len(key)) + key)
        result.extend(struct.pack(">H", len(raw)) + raw)

    attr(0x47, "attributes-charset", "utf-8")
    attr(0x48, "attributes-natural-language", "en")
    attr(0x45, "printer-uri", printer_uri)
    if job_id is not None:
        attr(0x21, "job-id", job_id)
    attr(0x42, "requesting-user-name", "printer-goblin")
    for index, name in enumerate(requested_attributes):
        attr(0x44, "requested-attributes" if index == 0 else "", name)
    if job_name is not None:
        attr(0x42, "job-name", job_name)
    if document_format is not None:
        attr(0x49, "document-format", document_format)
    if operation == 0x0002:  # Print-Job job template: request exactly one copy.
        result.extend(b"\x02\x21\x00\x06copies\x00\x04\x00\x00\x00\x01")
    return bytes(result) + b"\x03" + data


def _decode_value(tag: int, raw: bytes) -> object:
    if tag in (0x21, 0x23):
        return struct.unpack(">i", raw)[0]
    if tag == 0x22:
        if raw not in (b"\x00", b"\x01"):
            raise ValueError("invalid IPP boolean")
        return raw == b"\x01"
    if tag == 0x33:
        return struct.unpack(">ii", raw)
    if tag == 0x32:
        return struct.unpack(">iiB", raw)
    if tag in _TEXT_TAGS:
        return raw.decode("utf-8", errors="replace")
    return raw


def _decode_response(data: bytes) -> tuple[int, int, dict[str, list[object]]]:
    if len(data) < 9 or data[0] not in (1, 2):
        raise ValueError("invalid IPP header")
    status, request_id = struct.unpack_from(">HI", data, 2)
    offset = 8
    name = ""
    attributes: dict[str, list[object]] = {}

    def field() -> bytes:
        nonlocal offset
        length = struct.unpack_from(">H", data, offset)[0]
        offset += 2
        end = offset + length
        if end > len(data):
            raise ValueError("truncated IPP attribute")
        raw = data[offset:end]
        offset = end
        return raw

    try:
        while offset < len(data):
            tag = data[offset]
            offset += 1
            if tag == 3:
                return status, request_id, attributes
            if tag <= 0x0F:
                name = ""
                continue
            if tag == 0x7F:
                tag = struct.unpack_from(">I", data, offset)[0]
                offset += 4
            key, raw = field(), field()
            if key:
                name = key.decode("ascii")
            if not name:
                raise ValueError("IPP attribute value has no name")
            attributes.setdefault(name, []).append(_decode_value(tag, raw))
    except struct.error as exc:
        raise ValueError("invalid or truncated IPP attribute") from exc
    raise ValueError("missing IPP end-of-attributes tag")


def decode_response(data: bytes) -> dict[str, list[object]]:
    """Decode attributes by name, preserving all values."""
    return _decode_response(data)[2]


def _uri(host: str, port: int, path: str) -> str:
    authority = f"[{host.replace('%', '%25')}]" if ":" in host else host
    return f"ipp://{authority}:{port}{path}"


def _post(host: str, port: int, path: str, timeout: float,
          request: bytes, on_submit=None) -> tuple[int, bytes]:
    connection = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        connection.request("POST", path, request, {
            "Content-Type": "application/ipp", "Content-Length": str(len(request)),
        })
        if on_submit is not None:
            on_submit()
        response = connection.getresponse()
        if not 200 <= response.status < 300:
            return response.status, b""
        body = response.read(_MAX_RESPONSE + 1)
        if len(body) > _MAX_RESPONSE:
            raise ValueError("IPP response exceeds size limit")
        return response.status, body
    finally:
        connection.close()


def _checked_response(http_status: int, body: bytes) -> tuple[int, dict[str, list[object]]]:
    if not 200 <= http_status < 300:
        raise OSError(f"IPP HTTP status {http_status}")
    status, request_id, attributes = _decode_response(body)
    if request_id != 1:
        raise ValueError("unexpected IPP request ID")
    return status, attributes


def get_printer_attributes(host: str, port: int = 631, path: str = "/ipp/print",
                           timeout: float = 5) -> dict[str, list[object]]:
    """Query printer attributes, trying common paths on HTTP 400 or 404."""
    return query_printer(host, port, path, timeout)[0]


def query_printer(host: str, port: int = 631, path: str = "/ipp/print",
                  timeout: float = 5) -> tuple[dict[str, list[object]], str]:
    """Return attributes and the path that accepted the read-only query."""
    host = str(resolve_target(host))
    for endpoint in dict.fromkeys((path, "/", "/printers/")):
        request = encode_request(0x000B, _uri(host, port, endpoint),
                                 requested_attributes=REQUESTED_ATTRIBUTES)
        http_status, body = _post(host, port, endpoint, timeout, request)
        if http_status in (400, 404):
            continue
        status, attributes = _checked_response(http_status, body)
        if status >= 0x0100:
            raise OSError(f"Get-Printer-Attributes failed with IPP status 0x{status:04x}")
        return attributes, endpoint
    raise OSError(f"IPP printer path unavailable (HTTP {http_status})")


def print_job(host: str, data: bytes, document_format: str, port: int = 631,
              path: str = "/ipp/print", job_name: str = "Printer Goblin notice",
              timeout: float = 30, *, on_submit=None) -> tuple[int, Optional[int]]:
    """Submit a single Print-Job request and return its status and job ID."""
    host = str(resolve_target(host))
    request = encode_request(0x0002, _uri(host, port, path),
                             document_format=document_format, job_name=job_name, data=data)
    status, attributes = _checked_response(*_post(host, port, path, timeout, request, on_submit))
    job_id = next(iter(attributes.get("job-id", [])), None)
    return status, job_id if type(job_id) is int and job_id > 0 else None


def get_job_attributes(host: str, job_id: int, port: int = 631, path: str = "/ipp/print",
                       timeout: float = 5) -> dict[str, list[object]]:
    """Read the state, reasons, and impression count for a specific IPP job."""
    host = str(resolve_target(host))
    if type(job_id) is not int or not 1 <= job_id <= 0x7fffffff:
        raise ValueError("Invalid IPP job ID.")
    request = encode_request(
        0x0009, _uri(host, port, path), job_id=job_id,
        requested_attributes=("job-state", "job-state-reasons", "job-impressions-completed"),
    )
    status, attributes = _checked_response(*_post(host, port, path, timeout, request))
    if status >= 0x0100:
        raise OSError(f"Get-Job-Attributes failed with IPP status 0x{status:04x}")
    return attributes
