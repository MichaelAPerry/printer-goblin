"""Render a single PWG 5102.4 page in 8-bit standard grayscale."""

import struct

from . import _page
from .font_fixed import FIXED_16, FIXED_18
from .notice import Notice

# PageSize uses integer points. Raster dimensions use the physical media size
# in hundredths of a millimeter (2540 units per inch).
_MEDIA = {
    "letter": ("na_letter_8.5x11in", (612, 792), (21590, 27940)),
    "a4": ("iso_a4_210x297mm", (595, 842), (21000, 29700)),
}
_SYNC = b"RaS2"
_HEADER_SIZE = 1796
_WHITE = b"\xff"


def media_for(keyword: str | None) -> str:
    """Map an IPP media-default keyword to a supported page size."""
    return "a4" if keyword == _MEDIA["a4"][0] else "letter"


def _encode_line(row: bytes) -> bytearray:
    """Encode one sgray_8 line as runs of up to 128 pixels."""
    encoded = bytearray()
    start = 0
    while start < len(row):
        limit = min(start + 128, len(row))
        end = start + 1
        if end < limit and row[start] == row[end]:
            while end < limit and row[end] == row[start]:
                end += 1
            encoded.extend((end - start - 1, row[start]))
        else:
            # Stop before the first pair so the next packet can repeat it.
            while end < limit and (end + 1 == len(row) or row[end] != row[end + 1]):
                end += 1
            count = end - start
            if count == 1:
                encoded.extend((0, row[start]))
            else:
                encoded.append(257 - count)
                encoded.extend(row[start:end])
        start = end
    return encoded


def _encode_raster(pixels: bytearray, width: int) -> bytearray:
    encoded = bytearray()
    start = 0
    while start < len(pixels):
        row = pixels[start:start + width]
        end = start + width
        while (end < len(pixels) and end - start < 256 * width
               and pixels[end:end + width] == row):
            end += width
        encoded.append((end - start) // width - 1)
        encoded.extend(_encode_line(row))
        start = end
    return encoded


def _header(media, dpi, width, height, image_box):
    name, page_size, _ = _MEDIA[media]
    header = bytearray(_HEADER_SIZE)
    struct.pack_into(">64s", header, 0, b"PwgRaster")
    struct.pack_into(">2I", header, 276, dpi, dpi)
    struct.pack_into(">I", header, 340, 1)  # NumCopies
    struct.pack_into(">2I", header, 352, *page_size)
    struct.pack_into(">2I", header, 372, width, height)
    struct.pack_into(">5I", header, 384, 8, 8, width, 0, 18)
    struct.pack_into(">I", header, 420, 1)  # NumColors
    struct.pack_into(">I2i4I", header, 452, 1, 1, 1, *image_box)
    struct.pack_into(">64s", header, 1732, name.encode("ascii"))
    return header


def render(notice: Notice, dpi: int = 300, media: str = "letter") -> bytes:
    """Render the notice to a full-page, one-sided PWG Raster stream."""
    if media not in _MEDIA:
        raise ValueError("PWG media must be letter or a4")
    if type(dpi) is not int or dpi <= 0:
        raise ValueError("PWG resolution must be a positive integer")
    _, (page_width, _), (media_width, media_height) = _MEDIA[media]
    width, height = media_width * dpi // 2540, media_height * dpi // 2540

    def dot(points):
        return round(points * dpi / 72)

    image = _page.page_mascot(notice)
    headline, lines, qr_top, matrix = _page.layout(notice, image)
    body_scale = max(1, dpi // 96)
    mascot_x = _page.MASCOT_X - (612 - page_width)
    title_width = dot(mascot_x - _page.LEFT - 6 if image else page_width - 2 * _page.LEFT)
    title_scale = min(max(1, dpi // 48), title_width // (8 * len(headline) + 1))
    module = dot(_page.QR_WIDTH) // len(matrix)
    if (module < 1 or (headline and title_scale < 1)
            or dot(_page.LEFT) + max(len(line) for _, line in lines) * 8 * body_scale > width):
        raise ValueError("PWG resolution is too low for the notice layout")

    pixels = bytearray(_WHITE) * (width * height)
    left, top, right, bottom = width, height, 0, 0

    def ink(x, y, w, h):
        nonlocal left, top, right, bottom
        left, top = min(left, x), min(top, y)
        right, bottom = max(right, x + w), max(bottom, y + h)
        black = bytes(w)
        offset = y * width + x
        for _ in range(h):
            pixels[offset:offset + w] = black
            offset += width

    def draw_text(text, baseline, font, rows, scale, bold=False):
        y = dot(baseline) - rows * scale
        for index, char in enumerate(text):
            glyph = (ord(char) - 32) * rows
            for row, bits in enumerate(font[glyph:glyph + rows]):
                for column in range(8):
                    if bits & (128 >> column):
                        x = dot(_page.LEFT) + (index * 8 + column) * scale
                        ink(x, y + row * scale, scale * (2 if bold else 1), scale)

    if image:
        image_width = dot(_page.MASCOT_WIDTH)
        image_height = dot(_page.mascot_height(image))
        x0, y0 = dot(mascot_x), dot(_page.MASCOT_TOP)
        columns = [x * len(image[0]) // image_width for x in range(image_width)]
        for y in range(image_height):
            row = image[y * len(image) // image_height]
            for x, column in enumerate(columns):
                if row[column]:
                    ink(x0 + x, y0 + y, 1, 1)
    draw_text(headline, _page.HEADLINE_Y, FIXED_18, 18, title_scale, bold=True)
    for baseline, line in lines:
        draw_text(line, baseline, FIXED_16, 16, body_scale)
    for y, row in enumerate(matrix):
        for x, dark in enumerate(row):
            if dark:
                ink(dot(_page.LEFT) + x * module, dot(qr_top) + y * module, module, module)

    return bytes(_SYNC + _header(media, dpi, width, height, (left, top, right, bottom))
                 + _encode_raster(pixels, width))
