"""Render one notice as PCL5 text and uncompressed raster rows."""

from ..assets import pack_row
from ._page import (HEADLINE_Y, LEFT, MASCOT_TOP, MASCOT_X, QR_WIDTH,
                    headline_size, layout, page_mascot)
from .notice import Notice
from .qr import scale_matrix


def _position(y: int, x: int = LEFT) -> bytes:
    return f"\x1b*p{round(x * 300 / 72)}X\x1b*p{round(y * 300 / 72)}Y".encode("ascii")


def _raster(rows: list[list[bool]], top: int, left: int = LEFT) -> bytes:
    output = bytearray(_position(top, left))
    output.extend(f"\x1b*t300R\x1b*r{len(rows[0])}S\x1b*r{len(rows)}T".encode("ascii"))
    output.extend(b"\x1b*r1A\x1b*b0M")
    for row in rows:
        packed = pack_row(row)
        output.extend(f"\x1b*b{len(packed)}W".encode("ascii") + packed)
    output.extend(b"\x1b*rB")
    return bytes(output)


def render(notice: Notice) -> bytes:
    image = page_mascot(notice)
    headline, lines, top, matrix = layout(notice, image)
    output = bytearray(b"\x1bE\x1b&l1X\x1b&u300D")
    if image:
        output.extend(_raster(image, MASCOT_TOP, MASCOT_X))
    font = f"\x1b(s1p{headline_size(headline)}v0s3b52T".encode("ascii")
    output.extend(font + _position(HEADLINE_Y) + headline.encode("ascii"))
    output.extend(b"\x1b(s0p12h10v0s0b3T")
    for y, line in lines:
        output.extend(_position(y) + line.encode("ascii"))

    factor = max(1, round(QR_WIDTH * 300 / 72 / len(matrix)))
    output.extend(_raster(scale_matrix(matrix, factor), top) + b"\x0c\x1bE")
    return bytes(output)
