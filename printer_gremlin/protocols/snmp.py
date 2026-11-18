"""Read-only SNMPv1 printer identification."""

from __future__ import annotations

import secrets
import socket
import time
from typing import Iterable, Optional

from ..scope import resolve_target

OIDS = {
    "sysDescr": "1.3.6.1.2.1.1.1.0",
    "sysName": "1.3.6.1.2.1.1.5.0",
    "hrDeviceDescr": "1.3.6.1.2.1.25.3.2.1.3.1",
    "prtGeneralSerialNumber": "1.3.6.1.2.1.43.5.1.1.17.1",
}


def _tlv(tag: int, value: bytes) -> bytes:
    size = len(value)
    length = bytes([size]) if size < 128 else size.to_bytes((size.bit_length() + 7) // 8, "big")
    if size >= 128:
        length = bytes([0x80 | len(length)]) + length
    return bytes([tag]) + length + value


def _integer(value: int) -> bytes:
    size = (max(value.bit_length(), (~value).bit_length()) + 8) // 8
    return _tlv(2, value.to_bytes(size, "big", signed=True))


def _oid(value: str) -> bytes:
    first, second, *rest = map(int, value.split("."))
    if first not in (0, 1, 2) or second < 0 or (first < 2 and second > 39):
        raise ValueError("invalid SNMP OID")
    raw = bytearray()
    for part in (40 * first + second, *rest):
        if part < 0:
            raise ValueError("invalid SNMP OID")
        digits = [part & 0x7F]
        while part > 127:
            part >>= 7
            digits.append(0x80 | (part & 0x7F))
        raw.extend(reversed(digits))
    return _tlv(6, bytes(raw))


def encode_get(oids: Iterable[str], request_id: int, community: str = "public") -> bytes:
    """Encode an SNMPv1 GetRequest with NULL varbind values."""
    bindings = b"".join(_tlv(0x30, _oid(oid) + b"\x05\x00") for oid in oids)
    pdu = _integer(request_id) + _integer(0) * 2 + _tlv(0x30, bindings)
    return _tlv(0x30, _integer(0) + _tlv(4, community.encode()) + _tlv(0xA0, pdu))


class _Reader:
    def __init__(self, data: bytes):
        self.data = data
        self.offset = 0

    def __bool__(self) -> bool:
        return self.offset < len(self.data)

    def take(self, count: int) -> bytes:
        end = self.offset + count
        if end > len(self.data):
            raise ValueError("truncated BER")
        value = self.data[self.offset:end]
        self.offset = end
        return value

    def field(self, expected: Optional[int] = None) -> tuple[int, bytes]:
        tag, size = self.take(2)
        if expected is not None and tag != expected:
            raise ValueError("unexpected BER tag")
        if size >= 128:
            count = size & 127
            if not 1 <= count <= 4:
                raise ValueError("unsupported BER length")
            size = int.from_bytes(self.take(count), "big")
        return tag, self.take(size)

    def child(self, tag: int) -> _Reader:
        return _Reader(self.field(tag)[1])

    def integer(self) -> int:
        raw = self.field(2)[1]
        if not raw:
            raise ValueError("empty BER integer")
        return int.from_bytes(raw, "big", signed=True)


def _decode_oid(raw: bytes) -> str:
    parts = []
    part = 0
    for octet in raw:
        part = (part << 7) | (octet & 127)
        if not octet & 128:
            parts.append(part)
            part = 0
    if not parts or raw[-1] & 128:
        raise ValueError("invalid BER OID")
    combined, *rest = parts
    first = min(2, combined // 40)
    return ".".join(map(str, (first, combined - first * 40, *rest)))


def _decode_packet(data: bytes, request_id: Optional[int], community: str
                   ) -> tuple[int, int, dict[str, object]]:
    root = _Reader(data)
    message = root.child(0x30)
    if root or message.integer() != 0 or message.field(4)[1] != community.encode():
        raise ValueError("unexpected SNMP message")
    pdu = message.child(0xA2)
    received_id, error, error_index = pdu.integer(), pdu.integer(), pdu.integer()
    if request_id is not None and request_id != received_id:
        raise ValueError("unexpected SNMP request ID")
    bindings = pdu.child(0x30)
    if message or pdu:
        raise ValueError("trailing SNMP fields")
    values = {}
    while bindings:
        binding = bindings.child(0x30)
        oid = _decode_oid(binding.field(6)[1])
        tag, raw = binding.field()
        if binding:
            raise ValueError("trailing SNMP varbind fields")
        if tag == 4:
            value = raw.decode("utf-8", errors="replace")
        elif tag == 2:
            value = int.from_bytes(raw, "big", signed=True)
        elif tag in (0x41, 0x42, 0x43):
            value = int.from_bytes(raw, "big")
        else:
            value = raw
        values[oid] = value
    return error, error_index, values


def decode_response(data: bytes, request_id: Optional[int] = None,
                    community: str = "public") -> dict[str, object]:
    """Decode a successful GetResponse into values keyed by numeric OID."""
    error, _, values = _decode_packet(data, request_id, community)
    if error:
        raise ValueError(f"SNMP error status {error}")
    return values


def get_printer_values(host: str, community: str = "public", timeout: float = 2,
                       *, port: int = 161) -> dict[str, str]:
    """Collect available printer strings, retrying a timed-out GET once."""
    host = str(resolve_target(host))
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    names = {oid: name for name, oid in OIDS.items()}
    pending = list(names)
    try:
        with socket.socket(family, socket.SOCK_DGRAM) as sock:
            sock.connect((host, port))
            while pending:
                request_id = secrets.randbelow(2**31 - 1) + 1
                request = encode_get(pending, request_id, community)
                response = None
                for _ in range(2):
                    sock.send(request)
                    deadline = time.monotonic() + timeout
                    while time.monotonic() < deadline:
                        sock.settimeout(max(0.001, deadline - time.monotonic()))
                        try:
                            packet = sock.recv(65535)
                        except socket.timeout:
                            break
                        try:
                            response = _decode_packet(packet, request_id, community)
                        except ValueError:
                            continue
                        break
                    if response is not None:
                        break
                if response is None:
                    return {}
                error, index, values = response
                if error == 0:
                    return {names[oid]: value for oid, value in values.items()
                            if oid in pending and isinstance(value, str)}
                # SNMPv1 reports a missing OID as an error for the entire request.
                if error != 2 or not 1 <= index <= len(pending):
                    return {}
                del pending[index - 1]
    except OSError:
        pass
    return {}
