#!/usr/bin/env python3
"""Build the Printer Gremlin bitmaps from the two source PNGs."""

from pathlib import Path
import struct
import zlib

try:
    from PIL import Image
except ImportError:
    Image = None

ROOT = Path(__file__).resolve().parents[1]
ART = ROOT / "assets"
PACKAGE = ROOT / "printer_gremlin" / "assets"
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


def read_png(path):
    """Return width, height and packed RGB, composited on white."""
    if Image is not None:
        with Image.open(path) as image:
            rgba = image.convert("RGBA")
            white = Image.new("RGB", rgba.size, "white")
            white.paste(rgba, mask=rgba.getchannel("A"))
            return *white.size, white.tobytes()

    encoded = path.read_bytes()
    if not encoded.startswith(PNG_SIGNATURE):
        raise ValueError(f"{path}: invalid PNG signature")
    offset = len(PNG_SIGNATURE)
    compressed = bytearray()
    while offset < len(encoded):
        size, kind = struct.unpack_from(">I4s", encoded, offset)
        data = encoded[offset + 8:offset + 8 + size]
        offset += size + 12
        if kind == b"IHDR":
            width, height, depth, color, compression, filtering, interlace = (
                struct.unpack(">IIBBBBB", data)
            )
        elif kind == b"IDAT":
            compressed.extend(data)
        elif kind == b"IEND":
            break

    channels = {0: 1, 2: 3, 4: 2, 6: 4}.get(color)
    if depth != 8 or not channels or any((compression, filtering, interlace)):
        raise ValueError(f"{path}: expected non-interlaced 8-bit grayscale or RGB(A) PNG")
    stride = width * channels
    raw = zlib.decompress(compressed)
    if len(raw) != height * (stride + 1):
        raise ValueError(f"{path}: invalid PNG scanline data")

    previous = bytearray(stride)
    pixels = bytearray()
    for offset in range(0, len(raw), stride + 1):
        method = raw[offset]
        row = bytearray(raw[offset + 1:offset + stride + 1])
        if method not in range(5):
            raise ValueError(f"{path}: invalid PNG row filter {method}")
        if method:
            for i, value in enumerate(row):
                left = row[i - channels] if i >= channels else 0
                above = previous[i]
                upper_left = previous[i - channels] if i >= channels else 0
                if method == 1:
                    predicted = left
                elif method == 2:
                    predicted = above
                elif method == 3:
                    predicted = (left + above) // 2
                else:
                    estimate = left + above - upper_left
                    predicted = min(
                        (left, above, upper_left), key=lambda item: abs(estimate - item)
                    )
                row[i] = (value + predicted) & 255
        previous = row
        if color == 2:
            pixels.extend(row)
            continue
        for i in range(0, stride, channels):
            rgb = row[i:i + 3] if color == 6 else row[i:i + 1] * 3
            alpha = row[i + channels - 1] if color in (4, 6) else 255
            pixels.extend((value * alpha + 255 * (255 - alpha) + 127) // 255 for value in rgb)
    return width, height, bytes(pixels)


def png_bytes(width, height, rgb):
    if Image is not None:
        from io import BytesIO

        output = BytesIO()
        Image.frombytes("RGB", (width, height), rgb).save(output, format="PNG")
        return output.getvalue()

    def chunk(kind, data):
        return struct.pack(">I", len(data)) + kind + data + struct.pack(
            ">I", zlib.crc32(kind + data)
        )

    stride = width * 3
    scanlines = b"".join(b"\0" + rgb[i:i + stride] for i in range(0, len(rgb), stride))
    return (
        PNG_SIGNATURE
        + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(scanlines, 9))
        + chunk(b"IEND", b"")
    )


def remove_specks(ink, width, height):
    """Remove isolated black pixels using an eight-connected neighborhood."""
    clean = bytearray(ink)
    for i, black in enumerate(ink):
        if not black:
            continue
        y, x = divmod(i, width)
        neighbors = (
            j * width + k
            for j in range(max(0, y - 1), min(height, y + 2))
            for k in range(max(0, x - 1), min(width, x + 2))
        )
        if not any(ink[n] for n in neighbors if n != i):
            clean[i] = 0
    return clean


def trim_line_art(width, height, rgb):
    """Find the ink bounds using a luminance threshold of 128."""
    gray = bytes(
        (299 * r + 587 * g + 114 * b + 500) // 1000
        for r, g, b in zip(rgb[::3], rgb[1::3], rgb[2::3])
    )
    ink = remove_specks(bytearray(value < 128 for value in gray), width, height)
    points = [divmod(i, width) for i, black in enumerate(ink) if black]
    if not points:
        raise ValueError("Source PNG contains no ink at the chosen threshold")
    rows, columns = zip(*points)
    left, right = min(columns), max(columns) + 1
    top, bottom = min(rows), max(rows) + 1
    cropped = bytes(0 if black else 255 for black in ink)
    return right - left, bottom - top, b"".join(
        cropped[y * width + left:y * width + right] for y in range(top, bottom)
    )


def sample_positions(source_size, target_size):
    return [(2 * i + 1) * source_size // (2 * target_size) for i in range(target_size)]


def pbm_raster(source_width, source_height, gray, width):
    height = max(1, round(source_height * width / source_width))
    if Image is not None:
        resized = Image.frombytes("L", (source_width, source_height), gray).resize(
            (width, height), Image.Resampling.BOX
        ).tobytes()
    else:
        # Average the covered pixels when reducing so fine strokes retain coverage.
        x_edges = [i * source_width // width for i in range(width + 1)]
        y_edges = [i * source_height // height for i in range(height + 1)]
        resized = bytearray()
        for top, bottom in zip(y_edges, y_edges[1:]):
            bottom = max(top + 1, bottom)
            for left, right in zip(x_edges, x_edges[1:]):
                right = max(left + 1, right)
                total = sum(
                    sum(gray[y * source_width + left:y * source_width + right])
                    for y in range(top, bottom)
                )
                resized.append(total // ((bottom - top) * (right - left)))
    ink = remove_specks(bytearray(value < 128 for value in resized), width, height)
    return height, ink


def write_pbm(path, width, height, ink):
    stride = (width + 7) // 8
    packed = bytearray(stride * height)
    for i, black in enumerate(ink):
        if black:
            y, x = divmod(i, width)
            packed[y * stride + x // 8] |= 0x80 >> (x % 8)
    path.write_bytes(f"P4\n{width} {height}\n".encode("ascii") + packed)


def color_thumbnail(width, height, rgb):
    size = (max(1, round(width * 256 / max(width, height))),
            max(1, round(height * 256 / max(width, height))))
    if Image is not None:
        reduced = Image.frombytes("RGB", (width, height), rgb).resize(size, Image.Resampling.LANCZOS)
        return png_bytes(*size, reduced.tobytes())
    offsets = (
        (y * width + x) * 3
        for y in sample_positions(height, size[1])
        for x in sample_positions(width, size[0])
    )
    return png_bytes(*size, b"".join(rgb[i:i + 3] for i in offsets))


def main():
    PACKAGE.mkdir(parents=True, exist_ok=True)
    line_art = trim_line_art(*read_png(ART / "gremlin-source.png"))
    for width in (384, 576):
        height, ink = pbm_raster(*line_art, width)
        path = PACKAGE / f"gremlin_{width}.pbm"
        write_pbm(path, width, height, ink)
        print(f"{path.name}: {width} x {height}, {sum(ink) / len(ink):.2%} black, "
              f"{path.stat().st_size:,} bytes")
    thumbnail = color_thumbnail(*read_png(ART / "gremlin-color.png"))
    (ART / "gremlin-color-256.png").write_bytes(thumbnail)
    (PACKAGE / "gremlin_color_256.png").write_bytes(thumbnail)


if __name__ == "__main__":
    main()
