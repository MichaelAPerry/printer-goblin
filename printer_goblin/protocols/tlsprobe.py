"""Inspect TLS handshakes without sending application data."""

from __future__ import annotations

import socket
import ssl
import time
import warnings
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from ..net import actual_port
from ..scope import resolve_target


@dataclass
class TLSResult:
    version: Optional[str] = None
    cipher: Optional[str] = None
    self_signed: Optional[bool] = None
    not_after: Optional[str] = None
    expired: Optional[bool] = None
    legacy: str = "untestable"
    modern: Optional[bool] = None  # a default (TLS 1.2+) handshake completed


def _field(data: memoryview, tag: Optional[int] = None) -> tuple[memoryview, memoryview]:
    """Read a definite-length DER field and return its contents and remainder."""
    if len(data) < 2 or (tag is not None and data[0] != tag):
        raise ValueError("unexpected certificate field")
    size = data[1]
    start = 2
    if size >= 128:
        count = size & 127
        start += count
        if not 1 <= count <= 4 or start > len(data):
            raise ValueError("invalid certificate field length")
        size = int.from_bytes(data[2:start], "big")
    end = start + size
    if end > len(data):
        raise ValueError("truncated certificate field")
    return data[start:end], data[end:]


def _certificate_facts(cert: bytes, result: TLSResult) -> None:
    try:
        sequence, _ = _field(memoryview(cert), 0x30)
        body, _ = _field(sequence, 0x30)
        if body and body[0] == 0xA0:  # Optional explicit version
            _, body = _field(body, 0xA0)
        _, body = _field(body, 0x02)  # Serial
        _, body = _field(body, 0x30)  # Signature algorithm
        issuer, body = _field(body, 0x30)
        validity, body = _field(body, 0x30)
        subject, _ = _field(body, 0x30)
        # Match the encoded names. This checks self-issuance without verifying a signature.
        result.self_signed = issuer == subject
        _, expiry = _field(validity)  # Skip notBefore.
        tag = expiry[0] if expiry else None
        raw, _ = _field(expiry)
        value = bytes(raw).decode("ascii")
        if tag == 0x17 and len(value) == 13:
            value = ("19" if value[:2] >= "50" else "20") + value
        elif tag != 0x18 or len(value) != 15:
            return
        end = datetime.strptime(value, "%Y%m%d%H%M%SZ").replace(tzinfo=timezone.utc)
        result.not_after = end.isoformat()
        result.expired = end < datetime.now(timezone.utc)
    except ValueError:
        pass


def _context() -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def _handshake(context: ssl.SSLContext, host: str, port: int, timeout: float,
               result: Optional[TLSResult] = None) -> None:
    deadline = time.monotonic() + timeout
    with socket.create_connection((host, actual_port(host, port)), timeout) as sock:
        sock.settimeout(max(0.001, deadline - time.monotonic()))
        with context.wrap_socket(sock, server_hostname=host) as peer:
            if result is not None:
                result.version = peer.version()
                cipher = peer.cipher()
                result.cipher = cipher[0] if cipher else None
                cert = peer.getpeercert(binary_form=True)
                if cert:
                    _certificate_facts(cert, result)


def probe(host: str, port: int, timeout: float = 3) -> TLSResult:
    """Try a normal TLS handshake, then check for TLS 1.0/1.1 support."""
    host = str(resolve_target(host))
    timeout = min(timeout, 3)
    result = TLSResult()
    try:
        _handshake(_context(), host, port, timeout, result)
        result.modern = True
    except (OSError, ValueError):
        result.modern = False

    try:
        legacy = _context()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            legacy.minimum_version = ssl.TLSVersion.TLSv1
            legacy.maximum_version = ssl.TLSVersion.TLSv1_1
        legacy.set_ciphers("DEFAULT:@SECLEVEL=0")
    except (ssl.SSLError, ValueError):
        return result

    try:
        _handshake(legacy, host, port, timeout, None if result.version else result)
    except ssl.SSLError as exc:
        if exc.reason not in {"NO_PROTOCOLS_AVAILABLE", "NO_CIPHERS_AVAILABLE"}:
            result.legacy = "refused"
    except (ConnectionRefusedError, ConnectionResetError):
        result.legacy = "refused"
    except (OSError, ValueError):
        pass
    else:
        result.legacy = "accepted"
    return result
