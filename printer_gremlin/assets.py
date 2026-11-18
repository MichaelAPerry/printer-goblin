"""Load packaged monochrome raster artwork."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

ASSET_DIR = Path(__file__).with_name("assets")
_TOKEN = re.compile(rb"(?:\s+|#[^\r\n]*)*([^\s#]+)")


def load_pbm(name: str) -> Optional[list[list[bool]]]:
    """Read a P1 or P4 bitmap, with True representing a black dot."""
    try:
        data = (ASSET_DIR / Path(name).name).read_bytes()
    except FileNotFoundError:
        return None

    offset = 0

    def token() -> bytes:
        nonlocal offset
        match = _TOKEN.match(data, offset)
        if match is None:
            raise ValueError("incomplete PBM header or raster")
        offset = match.end()
        return match[1]

    magic, width, height = token(), int(token()), int(token())
    if magic not in (b"P1", b"P4") or width <= 0 or height <= 0:
        raise ValueError("invalid PBM header")
    if magic == b"P1":
        pixels = re.sub(rb"#[^\r\n]*|\s+", b"", data[offset:])
        if len(pixels) != width * height or set(pixels) - {48, 49}:
            raise ValueError("invalid P1 raster")
        return [[value == 49 for value in pixels[y:y + width]]
                for y in range(0, len(pixels), width)]

    # Consume the header delimiter without stripping any binary pixel bytes.
    if data[offset:offset + 1] == b"#":
        offset += len(re.match(rb"#[^\r\n]*", data[offset:])[0])
    delimiter = 2 if data[offset:offset + 2] == b"\r\n" else 1
    if offset == len(data) or data[offset] not in b" \t\r\n\v\f":
        raise ValueError("missing P4 raster delimiter")
    raster = data[offset + delimiter:]
    stride = (width + 7) // 8
    if len(raster) < stride * height:
        raise ValueError("incomplete P4 raster")
    return [[bool(raster[y * stride + x // 8] & (0x80 >> (x % 8)))
             for x in range(width)] for y in range(height)]


def mascot(width_px: int) -> Optional[list[list[bool]]]:
    """Choose the closest sufficiently wide mascot and scale down if needed."""
    if width_px <= 0:
        raise ValueError("mascot width must be positive")
    sizes = (384, 576) if width_px <= 384 else (576, 384)
    for size in sizes:
        rows = load_pbm(f"gremlin_{size}.pbm")
        if rows:
            width = len(rows[0])
            if width <= width_px:
                return rows
            height = max(1, round(len(rows) * width_px / width))
            return [[rows[y * len(rows) // height][x * width // width_px]
                     for x in range(width_px)] for y in range(height)]
    return None


def pack_row(row: list[bool]) -> bytes:
    packed = bytearray((len(row) + 7) // 8)
    for x, dark in enumerate(row):
        if dark:
            packed[x // 8] |= 0x80 >> (x % 8)
    return bytes(packed)
