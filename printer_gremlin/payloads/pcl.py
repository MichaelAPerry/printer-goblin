"""Render one notice as PCL5 text and uncompressed raster rows."""

from ._page import HEADLINE_Y, LEFT, QR_WIDTH, headline_size, layout
from .notice import Notice
from .qr import scale_matrix


def _position(y: int) -> bytes:
    return f"\x1b*p{round(LEFT * 300 / 72)}X\x1b*p{round(y * 300 / 72)}Y".encode("ascii")


def render(notice: Notice) -> bytes:
    headline, lines, top, matrix = layout(notice)
    output = bytearray(b"\x1bE\x1b&l1X\x1b&u300D")
    font = f"\x1b(s1p{headline_size(headline)}v0s3b52T".encode("ascii")
    output.extend(font + _position(HEADLINE_Y) + headline.encode("ascii"))
    output.extend(b"\x1b(s0p12h10v0s0b3T")
    for y, line in lines:
        output.extend(_position(y) + line.encode("ascii"))

    factor = max(1, round(QR_WIDTH * 300 / 72 / len(matrix)))
    rows = scale_matrix(matrix, factor)
    pixels = len(rows)
    output.extend(_position(top) + f"\x1b*t300R\x1b*r{pixels}S\x1b*r{pixels}T".encode("ascii"))
    output.extend(b"\x1b*r1A\x1b*b0M")
    for row in rows:
        packed = bytearray((pixels + 7) // 8)
        for x, dark in enumerate(row):
            if dark:
                packed[x // 8] |= 0x80 >> (x % 8)
        output.extend(f"\x1b*b{len(packed)}W".encode("ascii") + packed)
    output.extend(b"\x1b*rB\x0c\x1bE")
    return bytes(output)
