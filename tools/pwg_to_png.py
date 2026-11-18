"""Convert a single sgray_8 PWG page to a quarter-scale grayscale PNG."""

import argparse
import struct
import zlib
from pathlib import Path


def decode_rows(data, width, height):
    """Yield decompressed rows from a PWG 8-bit raster bitmap."""
    offset = 0
    remaining = height
    while remaining:
        if offset >= len(data):
            raise ValueError("missing PWG scanline")
        repetitions = data[offset] + 1
        offset += 1
        if repetitions > remaining:
            raise ValueError("PWG scanline repeats past the end of the page")

        row = bytearray()
        while len(row) < width:
            if offset >= len(data):
                raise ValueError("missing PWG run")
            control = data[offset]
            offset += 1
            if control == 128:
                raise ValueError("invalid PWG run control 128")
            length = control + 1 if control < 128 else 257 - control
            stored = 1 if control < 128 else length
            packet = data[offset:offset + stored]
            if len(packet) != stored or len(row) + length > width:
                raise ValueError("invalid PWG run length")
            row.extend(packet * length if control < 128 else packet)
            offset += stored
        remaining -= repetitions
        line = bytes(row)
        for _ in range(repetitions):
            yield line
    if offset != len(data):
        raise ValueError("unexpected data after PWG page")


def to_png(data):
    if len(data) < 1800 or data[:4] != b"RaS2" or data[4:14] != b"PwgRaster\0":
        raise ValueError("expected a PWG Raster header")
    width, height = struct.unpack_from(">2I", data, 4 + 372)
    fields = struct.unpack_from(">5I", data, 4 + 384)
    if not width or not height or fields != (8, 8, width, 0, 18):
        raise ValueError("expected a chunky 8-bit grayscale PWG page")
    pixels = bytearray()
    rows = iter(decode_rows(data[1800:], width, height))
    for y in range(0, height, 4):
        block = [next(rows) for _ in range(min(4, height - y))]
        pixels.append(0)  # PNG filter: None
        for x in range(0, width, 4):
            samples = sum(sum(row[x:x + 4]) for row in block)
            pixels.append(samples // (len(block) * min(4, width - x)))
    next(rows, None)  # Check for trailing bytes.

    def chunk(kind, value):
        return (struct.pack(">I", len(value)) + kind + value
                + struct.pack(">I", zlib.crc32(kind + value)))

    header = struct.pack(">2I5B", (width + 3) // 4, (height + 3) // 4, 8, 0, 0, 0, 0)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", header)
            + chunk(b"IDAT", zlib.compress(pixels)) + chunk(b"IEND", b""))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    try:
        args.output.write_bytes(to_png(args.source.read_bytes()))
    except (ValueError, OSError) as exc:
        parser.exit(1, f"{exc}\n")


if __name__ == "__main__":
    main()
