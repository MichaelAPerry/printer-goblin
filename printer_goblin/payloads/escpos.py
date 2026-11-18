"""A deliberately tiny, allowlisted ESC/POS command builder.

Why not python-escpos? It is excellent, but it exposes cash-drawer pulses,
NV memory writes, and many other peripheral controls. This builder can only
emit the handful of commands listed in ALLOWED_COMMANDS, and every job is
built from typed segments so arbitrary bytes cannot sneak in through text.

Never emitted (by construction):
  ESC p / DLE DC4 fn1   cash-drawer kick pulse
  DLE DC4 fn2           power-off sequence
  ESC = / ESC c ...     peripheral selection, panel-button lock
  GS ( E / FS q / GS ( L store   user-setup and NV memory writes
  ESC ( A / ESC B       buzzer
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Tuple

ESC = 0x1B
GS = 0x1D

# command name -> exact byte prefix it must start with
ALLOWED_COMMANDS = {
    "init": bytes([ESC, 0x40]),             # ESC @
    "align": bytes([ESC, 0x61]),            # ESC a n
    "bold": bytes([ESC, 0x45]),             # ESC E n
    "size": bytes([GS, 0x21]),              # GS ! n
    "feed": bytes([ESC, 0x64]),             # ESC d n
    "qr": bytes([GS, 0x28, 0x6B]),          # GS ( k  (fn 165/167/169/180/181)
    "raster": bytes([GS, 0x76, 0x30]),      # GS v 0  (print raster image)
    "cut": bytes([GS, 0x56]),               # GS V    (paper cut)
}

# Function codes allowed inside GS ( k for symbol type 49 (QR).
_QR_FUNCTIONS = {65, 67, 69, 80, 81}


class UnsafeCommandError(ValueError):
    pass


@dataclass
class EscPosJob:
    segments: List[Tuple[str, bytes]] = field(default_factory=list)

    # --- text --------------------------------------------------------
    def text(self, s: str) -> "EscPosJob":
        data = s.encode("ascii", "replace")
        clean = bytes(b if (0x20 <= b < 0x7F or b == 0x0A) else 0x3F for b in data)
        self.segments.append(("text", clean))
        return self

    def line(self, s: str = "") -> "EscPosJob":
        return self.text(s + "\n")

    # --- formatting --------------------------------------------------
    def init(self) -> "EscPosJob":
        self.segments.append(("init", ALLOWED_COMMANDS["init"]))
        return self

    def align(self, where: str) -> "EscPosJob":
        n = {"left": 0, "center": 1, "right": 2}[where]
        self.segments.append(("align", ALLOWED_COMMANDS["align"] + bytes([n])))
        return self

    def bold(self, on: bool) -> "EscPosJob":
        self.segments.append(("bold", ALLOWED_COMMANDS["bold"] + bytes([1 if on else 0])))
        return self

    def size(self, width: int = 1, height: int = 1) -> "EscPosJob":
        if not (1 <= width <= 8 and 1 <= height <= 8):
            raise ValueError("size multipliers must be 1..8")
        n = ((width - 1) << 4) | (height - 1)
        self.segments.append(("size", ALLOWED_COMMANDS["size"] + bytes([n])))
        return self

    def feed(self, lines: int) -> "EscPosJob":
        lines = max(0, min(lines, 10))
        self.segments.append(("feed", ALLOWED_COMMANDS["feed"] + bytes([lines])))
        return self

    def cut(self) -> "EscPosJob":
        # GS V 66 n: feed n and partial cut. Printers without a cutter ignore it.
        self.segments.append(("cut", ALLOWED_COMMANDS["cut"] + bytes([66, 3])))
        return self

    # --- QR (native GS ( k) -------------------------------------------
    def qr_native(self, data: str, module_size: int = 6) -> "EscPosJob":
        payload = data.encode("ascii")
        if len(payload) > 300:
            raise ValueError("QR payload too long for a notice")
        module_size = max(1, min(module_size, 16))

        def gs_k(fn: int, args: bytes) -> bytes:
            body = bytes([49, fn]) + args
            n = len(body)
            return ALLOWED_COMMANDS["qr"] + bytes([n & 0xFF, n >> 8]) + body

        seq = (
            gs_k(65, bytes([50, 0]))            # model 2
            + gs_k(67, bytes([module_size]))    # module size
            + gs_k(69, bytes([49]))             # error correction M
            + gs_k(80, bytes([48]) + payload)   # store data
            + gs_k(81, bytes([48]))             # print
        )
        self.segments.append(("qr", seq))
        return self

    # --- QR (raster fallback, works on printers without GS ( k) --------
    def raster(self, rows: List[List[bool]]) -> "EscPosJob":
        """Print a 1-bit image. rows[y][x] True = black."""
        height = len(rows)
        width = len(rows[0]) if rows else 0
        if not (0 < width <= 576 and 0 < height <= 1200):
            raise ValueError("raster image out of range")
        xbytes = (width + 7) // 8
        out = bytearray(ALLOWED_COMMANDS["raster"])
        out += bytes([0, xbytes & 0xFF, xbytes >> 8, height & 0xFF, height >> 8])
        for row in rows:
            for bx in range(xbytes):
                b = 0
                for bit in range(8):
                    x = bx * 8 + bit
                    if x < width and row[x]:
                        b |= 0x80 >> bit
                out.append(b)
        self.segments.append(("raster", bytes(out)))
        return self

    # --- output ------------------------------------------------------
    def validate(self) -> None:
        for name, data in self.segments:
            if name == "text":
                if any(b < 0x20 and b != 0x0A for b in data) or any(b >= 0x7F for b in data):
                    raise UnsafeCommandError("control byte inside text segment")
                continue
            prefix = ALLOWED_COMMANDS.get(name)
            if prefix is None or not data.startswith(prefix):
                raise UnsafeCommandError(f"segment {name!r} is not an allowlisted command")
            if name == "qr":
                _check_qr(data)

    def to_bytes(self) -> bytes:
        self.validate()
        return b"".join(data for _, data in self.segments)


def _check_qr(data: bytes) -> None:
    i = 0
    prefix = ALLOWED_COMMANDS["qr"]
    while i < len(data):
        if data[i : i + 3] != prefix:
            raise UnsafeCommandError("malformed GS ( k sequence")
        n = data[i + 3] | (data[i + 4] << 8)
        cn, fn = data[i + 5], data[i + 6]
        if cn != 49 or fn not in _QR_FUNCTIONS:
            raise UnsafeCommandError(f"GS ( k function {cn}/{fn} not allowed")
        i += 5 + n
