"""A fake network printer for demos and end-to-end tests (loopback only).

Starts threaded listeners on ephemeral high ports (no root needed) and records
everything they receive. Clients reach them through ``net.port_overrides``,
which maps the logical printer ports (631, 9100, ...) to the real ones.
"""

from __future__ import annotations

import ipaddress
import socket
import socketserver
import struct
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable, Optional

from .protocols import ipp, snmp

LOGICAL_PORTS = (9100, 631, 515, 80, 443, 161, 21, 22, 23, 445, 5357, 8080, 8443)

# IPP operation and status codes used here.
OP_PRINT_JOB, OP_VALIDATE_JOB, OP_GET_JOB_ATTRIBUTES, OP_GET_PRINTER_ATTRIBUTES = 0x0002, 0x0004, 0x0009, 0x000B
OK, NOT_AUTHORIZED, NOT_FOUND, NOT_SUPPORTED = 0x0000, 0x0403, 0x0406, 0x0501
_OPERATIONS = (OP_PRINT_JOB, OP_VALIDATE_JOB, OP_GET_JOB_ATTRIBUTES, OP_GET_PRINTER_ATTRIBUTES)


@dataclass(frozen=True)
class Profile:
    ipp: bool = False
    ipp_auth: tuple[str, ...] = ("none",)
    accepts_jobs: bool = True
    formats: tuple[str, ...] = ()
    model: str = ""
    firmware: str = ""
    snmp: Optional[dict[str, str]] = None
    raw: bool = False
    http_title: Optional[str] = None
    lpd: bool = False


PROFILES: dict[str, Profile] = {
    "office-open": Profile(
        ipp=True, ipp_auth=("none",), formats=("image/pwg-raster", "image/urf"),
        model="Goblin Labs FakeJet 100", firmware="FJ-1.04",
        snmp={"sysDescr": "Goblin Labs FakeJet 100", "sysName": "FAKEJET100",
              "hrDeviceDescr": "Goblin Labs FakeJet 100"},
        raw=True, http_title="Goblin Labs FakeJet 100", lpd=True),
    "office-locked": Profile(
        ipp=True, ipp_auth=("requesting-user-name", "basic"), accepts_jobs=False,
        formats=("application/pdf", "image/pwg-raster"),
        model="Goblin Labs FakeJet 200 (locked)", firmware="FJ-2.00"),
    "receipt": Profile(
        snmp={"sysDescr": "EPSON TM-T88VI", "sysName": "TM-T88VI", "hrDeviceDescr": "EPSON TM-T88VI"},
        raw=True),
}


# --------------------------------------------------------------------------
# IPP server side
# --------------------------------------------------------------------------

def _parse_ipp_request(data: bytes) -> tuple[int, int, dict[str, list[object]], bytes]:
    """Return (operation, request_id, operation/job attributes, document bytes)."""
    if len(data) < 9 or data[0] not in (1, 2):
        raise ValueError("invalid IPP header")
    operation, request_id = struct.unpack_from(">HI", data, 2)
    offset, name = 8, ""
    attrs: dict[str, list[object]] = {}
    while offset < len(data):
        tag = data[offset]
        offset += 1
        if tag == 3:
            return operation, request_id, attrs, data[offset:]
        if tag <= 0x0F:
            name = ""
            continue
        parts = []
        for _ in range(2):
            (length,) = struct.unpack_from(">H", data, offset)
            parts.append(data[offset + 2:offset + 2 + length])
            offset += 2 + length
        if parts[0]:
            name = parts[0].decode("ascii")
        attrs.setdefault(name, []).append(ipp._decode_value(tag, parts[1]))
    raise ValueError("missing IPP end-of-attributes tag")


def _encode_ipp_response(status: int, request_id: int,
                         groups: tuple[tuple[int, list[tuple[str, int, list]]], ...] = ()) -> bytes:
    out = bytearray(struct.pack(">BBHI", 1, 1, status, request_id))
    base = [("attributes-charset", 0x47, ["utf-8"]), ("attributes-natural-language", 0x48, ["en"])]
    for group, attributes in ((0x01, base), *groups):
        out.append(group)
        for name, tag, values in attributes:
            for index, value in enumerate(values):
                if isinstance(value, bool):
                    raw = b"\x01" if value else b"\x00"
                elif isinstance(value, int):
                    raw = struct.pack(">i", value)
                else:
                    raw = value.encode("utf-8")
                key = name.encode("ascii") if index == 0 else b""
                out += bytes([tag]) + struct.pack(">H", len(key)) + key + struct.pack(">H", len(raw)) + raw
    return bytes(out) + b"\x03"


# --------------------------------------------------------------------------
# Emulator
# --------------------------------------------------------------------------

class _Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True


class FakePrinter:
    """Context manager running one fake printer profile on loopback."""

    def __init__(self, profile: str, host: str = "127.0.0.1", *, job_delay: float = 0.5,
                 on_event: Optional[Callable[[str], None]] = None):
        if profile not in PROFILES:
            raise ValueError(f"unknown profile {profile!r}; choose from {', '.join(PROFILES)}")
        if not ipaddress.ip_address(host).is_loopback:
            raise ValueError("the fake printer only listens on loopback")
        self.profile_name, self.profile, self.host = profile, PROFILES[profile], host
        self.job_delay, self.on_event = job_delay, on_event
        self.port_map: dict[int, int] = {}
        self.closed_port = 0
        self.jobs: list[dict] = []          # accepted IPP jobs (document bytes stored)
        self.ipp_requests: list[dict] = []  # every IPP request, accepted or not
        self.raw_connections: list[bytes] = []  # bytes per port-9100 connection (probes are empty)
        self.raw_jobs: list[bytes] = []     # the non-empty ones
        self.snmp_requests: list[dict] = []
        self.http_requests: list[str] = []
        self.lpd_connections = 0
        self._lock = threading.Lock()
        self._closers: list[Callable[[], None]] = []
        self._holders: list[socket.socket] = []
        self._next_job = 1

    # -- lifecycle ---------------------------------------------------------
    def __enter__(self) -> "FakePrinter":
        self.start()
        return self

    def __exit__(self, *exc) -> None:
        self.stop()

    def start(self) -> None:
        p = self.profile
        try:
            if p.ipp:
                self._serve_http(631, _ipp_handler(self))
            if p.raw:
                self._serve_tcp(9100, _raw_handler(self))
            if p.http_title is not None:
                self._serve_http(80, _web_handler(self))
            if p.lpd:
                self._serve_tcp(515, _lpd_handler(self))
            if p.snmp is not None:
                self._serve_snmp()
            # Borrow a free ephemeral port and release it: nothing is bound there, so every OS
            # answers with a refusal (a bound-but-not-listening socket times out on macOS/Windows).
            with socket.socket(self._family(), socket.SOCK_STREAM) as probe:
                probe.bind((self.host, 0))
                self.closed_port = probe.getsockname()[1]
        except BaseException:
            self.stop()
            raise

    def stop(self) -> None:
        for close in reversed(self._closers):
            close()
        self._closers.clear()
        for holder in self._holders:
            holder.close()
        self._holders.clear()

    def overrides(self) -> dict[int, int]:
        """Logical -> actual ports for every well-known port, closed ones included."""
        return {port: self.port_map.get(port, self.closed_port) for port in LOGICAL_PORTS}

    # -- helpers -----------------------------------------------------------
    def _family(self) -> int:
        return socket.AF_INET6 if ":" in self.host else socket.AF_INET

    def _log(self, message: str) -> None:
        if self.on_event is not None:
            self.on_event(message)

    def _serve_tcp(self, logical: int, handler) -> None:
        server = _Server((self.host, 0), handler)
        self._run(logical, server, server.server_address[1])

    def _serve_http(self, logical: int, handler) -> None:
        server = ThreadingHTTPServer((self.host, 0), handler)
        self._run(logical, server, server.server_address[1])

    def _run(self, logical: int, server, actual: int) -> None:
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        thread.start()
        self.port_map[logical] = actual

        def close() -> None:
            server.shutdown()
            server.server_close()
            thread.join(2)
        self._closers.append(close)

    def _serve_snmp(self) -> None:
        sock = socket.socket(self._family(), socket.SOCK_DGRAM)
        sock.bind((self.host, 0))
        sock.settimeout(0.05)
        stop = threading.Event()

        def loop() -> None:
            while not stop.is_set():
                try:
                    packet, peer = sock.recvfrom(65535)
                except socket.timeout:
                    continue
                except OSError:
                    return
                reply = self.snmp_reply(packet)
                if reply is not None:
                    sock.sendto(reply, peer)

        thread = threading.Thread(target=loop, daemon=True)
        thread.start()
        self.port_map[161] = sock.getsockname()[1]

        def close() -> None:
            stop.set()
            thread.join(2)
            sock.close()
        self._closers.append(close)

    def wait_for(self, predicate: Callable[[], bool], timeout: float = 3.0) -> bool:
        deadline = time.monotonic() + timeout
        while not predicate():
            if time.monotonic() > deadline:
                return False
            time.sleep(0.01)
        return True

    # -- SNMP --------------------------------------------------------------
    def snmp_reply(self, packet: bytes) -> Optional[bytes]:
        """Answer a SNMPv1 GET for community "public"; ignore everything else."""
        try:
            root = snmp._Reader(packet)
            message = root.child(0x30)
            if message.integer() != 0:
                return None
            community = message.field(4)[1]
            tag, body = message.field()
            if tag != 0xA0 or community != b"public":   # only GetRequest, only "public"
                return None
            pdu = snmp._Reader(body)
            request_id = pdu.integer()
            pdu.integer(), pdu.integer()
            bindings = pdu.child(0x30)
            oids = []
            while bindings:
                oids.append(snmp._decode_oid(bindings.child(0x30).field(6)[1]))
        except ValueError:
            return None
        known = {snmp.OIDS[name]: value for name, value in (self.profile.snmp or {}).items()}
        with self._lock:
            self.snmp_requests.append({"oids": oids})
        error, index, out = 0, 0, b""
        for position, oid in enumerate(oids, 1):
            if oid not in known and not error:
                error, index = 2, position  # noSuchName
            value = known.get(oid)
            out += snmp._tlv(0x30, snmp._oid(oid) + (snmp._tlv(4, value.encode()) if value is not None
                                                      else b"\x05\x00"))
        response = snmp._integer(request_id) + snmp._integer(error) + snmp._integer(index) + snmp._tlv(0x30, out)
        self._log(f"SNMP GET {len(oids)} OID(s)")
        return snmp._tlv(0x30, snmp._integer(0) + snmp._tlv(4, b"public") + snmp._tlv(0xA2, response))

    # -- IPP ---------------------------------------------------------------
    def ipp_reply(self, body: bytes) -> bytes:
        try:
            operation, request_id, attrs, document = _parse_ipp_request(body)
        except (ValueError, struct.error):
            return _encode_ipp_response(0x0400, 1)  # client-error-bad-request
        record = {"operation": operation, "attributes": attrs, "document_bytes": len(document)}
        with self._lock:
            self.ipp_requests.append(record)
        p = self.profile
        self._log(f"IPP operation 0x{operation:04x}")
        if operation == OP_GET_PRINTER_ATTRIBUTES:
            return _encode_ipp_response(OK, request_id, ((0x04, self._printer_attributes()),))
        if operation in (OP_PRINT_JOB, OP_VALIDATE_JOB):
            if not p.accepts_jobs:
                record["status"] = NOT_AUTHORIZED
                return _encode_ipp_response(NOT_AUTHORIZED, request_id)
            record["status"] = OK
            if operation == OP_VALIDATE_JOB:
                return _encode_ipp_response(OK, request_id)  # never stores a document
            with self._lock:
                job_id, self._next_job = self._next_job, self._next_job + 1
                self.jobs.append({
                    "job_id": job_id, "document": document, "created": time.monotonic(),
                    "format": next(iter(attrs.get("document-format", [])), None),
                    "name": next(iter(attrs.get("job-name", [])), None),
                    "copies": next(iter(attrs.get("copies", [])), None),
                })
            self._log(f"Print-Job {job_id}: {len(document)} bytes")
            return _encode_ipp_response(OK, request_id, ((0x02, [
                ("job-id", 0x21, [job_id]), ("job-state", 0x23, [3]),
                ("job-state-reasons", 0x44, ["job-incoming"])]),))
        if operation == OP_GET_JOB_ATTRIBUTES:
            wanted = next(iter(attrs.get("job-id", [])), None)
            with self._lock:
                job = next((j for j in self.jobs if j["job_id"] == wanted), None)
            if job is None:
                return _encode_ipp_response(NOT_FOUND, request_id)
            done = time.monotonic() - job["created"] >= self.job_delay
            return _encode_ipp_response(OK, request_id, ((0x02, [
                ("job-id", 0x21, [wanted]),
                ("job-state", 0x23, [9 if done else 5]),
                ("job-state-reasons", 0x44, ["job-completed-successfully" if done else "job-printing"]),
                ("job-impressions-completed", 0x21, [1 if done else 0])]),))
        return _encode_ipp_response(NOT_SUPPORTED, request_id)

    def _printer_attributes(self) -> list[tuple[str, int, list]]:
        p = self.profile
        return [
            ("printer-make-and-model", 0x41, [p.model]),
            ("printer-info", 0x41, [p.model]),
            ("printer-state", 0x23, [3]),
            ("printer-state-reasons", 0x44, ["none"]),
            ("printer-is-accepting-jobs", 0x22, [True]),
            ("ipp-versions-supported", 0x44, ["1.1", "2.0"]),
            ("document-format-supported", 0x49, list(p.formats)),
            ("printer-firmware-string-version", 0x41, [p.firmware]),
            ("printer-uri-supported", 0x45, [f"ipp://{self.host}:631/ipp/print"] * len(p.ipp_auth)),
            ("uri-authentication-supported", 0x44, list(p.ipp_auth)),
            ("uri-security-supported", 0x44, ["none"] * len(p.ipp_auth)),
            ("operations-supported", 0x23, list(_OPERATIONS)),
            ("media-default", 0x44, ["na_letter_8.5x11in"]),
        ]


def _ipp_handler(fake: FakePrinter):
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length)
            if self.path != "/ipp/print":
                self.send_error(404)
                return
            data = fake.ipp_reply(body)
            self.send_response(200)
            self.send_header("Content-Type", "application/ipp")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *args) -> None:
            pass
    return Handler


def _web_handler(fake: FakePrinter):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            with fake._lock:
                fake.http_requests.append(self.path)
            fake._log(f"HTTP GET {self.path}")
            if self.path != "/":
                self.send_error(404)
                return
            title = fake.profile.http_title
            data = (f"<!doctype html><html><head><title>{title}</title></head>"
                    f"<body><h1>{title}</h1><p>Fake printer for Printer Goblin demos.</p>"
                    "</body></html>").encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *args) -> None:
            pass
    return Handler


def _raw_handler(fake: FakePrinter):
    class Handler(socketserver.BaseRequestHandler):
        def handle(self) -> None:
            self.request.settimeout(5)
            chunks = []
            try:
                while chunk := self.request.recv(65536):
                    chunks.append(chunk)
            except OSError:
                pass
            data = b"".join(chunks)
            with fake._lock:
                fake.raw_connections.append(data)
                if data:
                    fake.raw_jobs.append(data)
            fake._log(f"Raw 9100: {len(data)} bytes")
    return Handler


def _lpd_handler(fake: FakePrinter):
    class Handler(socketserver.BaseRequestHandler):
        def handle(self) -> None:  # connect-only: accept and close
            with fake._lock:
                fake.lpd_connections += 1
            fake._log("LPD connection (closed)")
    return Handler


# --------------------------------------------------------------------------
# Test helpers
# --------------------------------------------------------------------------

def pwg_pages(data: bytes) -> int:
    """Validate a PWG Raster stream (RaS2) and return its page count."""
    if data[:4] != b"RaS2":
        raise ValueError("missing RaS2 sync word")
    offset, pages = 4, 0
    while offset < len(data):
        header = data[offset:offset + 1796]
        if len(header) < 1796:
            raise ValueError("truncated page header")
        offset += 1796
        height, = struct.unpack_from(">I", header, 376)
        bytes_per_line, = struct.unpack_from(">I", header, 392)
        bits_per_pixel, = struct.unpack_from(">I", header, 388)
        pixel = bits_per_pixel // 8
        row = 0
        while row < height:
            repeat = data[offset] + 1
            offset += 1
            got = 0
            while got < bytes_per_line:
                count = data[offset]
                offset += 1
                if count < 128:
                    got += (count + 1) * pixel
                    offset += pixel
                else:
                    got += (257 - count) * pixel
                    offset += (257 - count) * pixel
            if got != bytes_per_line:
                raise ValueError("raster line overruns BytesPerLine")
            row += repeat
        if row != height or offset > len(data):
            raise ValueError("raster data does not match page height")
        pages += 1
    return pages


def escpos_commands(data: bytes) -> list[str]:
    """Name each ESC/POS command in a byte stream.

    Dangerous or unrecognised sequences are prefixed ``unsafe:`` / ``unknown:``
    so tests can assert a job never contains them. Raster and QR payloads are
    skipped by length, so bytes inside them are never misread as commands.
    """
    out: list[str] = []
    i, n = 0, len(data)
    text = 0

    def flush() -> None:
        nonlocal text
        if text:
            out.append(f"text({text})")
            text = 0

    while i < n:
        b = data[i]
        if 0x20 <= b < 0x7F or b == 0x0A:
            text += 1
            i += 1
            continue
        flush()
        nxt = data[i + 1] if i + 1 < n else -1
        if b == 0x1B:
            if nxt == 0x40: out.append("init"); i += 2
            elif nxt == 0x61: out.append(f"align({data[i + 2]})"); i += 3
            elif nxt == 0x45: out.append(f"bold({data[i + 2]})"); i += 3
            elif nxt == 0x64: out.append(f"feed({data[i + 2]})"); i += 3
            elif nxt == 0x70: out.append("unsafe:drawer-pulse(ESC p)"); i += 5
            elif nxt == 0x28 and i + 2 < n and data[i + 2] == 0x41:
                out.append("unsafe:buzzer(ESC ( A)"); i += 5 + (data[i + 3] | data[i + 4] << 8)
            elif nxt == 0x42: out.append("unsafe:buzzer(ESC B)"); i += 4
            elif nxt in (0x3D, 0x63): out.append(f"unsafe:peripheral(ESC {chr(nxt)})"); i += 3
            else: out.append(f"unknown:ESC 0x{nxt & 0xFF:02x}"); i += 2
        elif b == 0x1D:
            if nxt == 0x21: out.append(f"size({data[i + 2]:#04x})"); i += 3
            elif nxt == 0x56:
                m = data[i + 2]
                out.append("cut"); i += 4 if m in (65, 66) else 3
            elif nxt == 0x76 and data[i + 2] == 0x30:
                xb, yb = data[i + 4] | data[i + 5] << 8, data[i + 6] | data[i + 7] << 8
                out.append(f"raster({xb * 8}x{yb})"); i += 8 + xb * yb
            elif nxt == 0x28 and i + 4 < n:
                length = data[i + 3] | data[i + 4] << 8
                kind = chr(data[i + 2])
                if kind == "k":
                    out.append(f"qr(fn={data[i + 6]})")
                elif kind == "E":
                    out.append("unsafe:nv-write(GS ( E)")
                elif kind == "L":
                    out.append("unsafe:nv-graphics(GS ( L)")
                else:
                    out.append(f"unknown:GS ( {kind}")
                i += 5 + length
            else: out.append(f"unknown:GS 0x{nxt & 0xFF:02x}"); i += 2
        elif b == 0x10:
            out.append("unsafe:DLE DC4" if nxt == 0x14 else f"unsafe:DLE 0x{nxt & 0xFF:02x}")
            i += 2
        elif b == 0x1C:
            out.append(f"unsafe:FS 0x{nxt & 0xFF:02x}"); i += 2
        else:
            out.append(f"unknown:control 0x{b:02x}"); i += 1
    flush()
    return out
