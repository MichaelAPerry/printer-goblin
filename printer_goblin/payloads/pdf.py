"""Render one notice as a minimal PDF 1.4 document."""

from ..assets import pack_row
from ._page import (HEADLINE_Y, LEFT, MASCOT_TOP, MASCOT_WIDTH, MASCOT_X, QR_WIDTH,
                    headline_size, layout, mascot_height, page_mascot, literal)
from .notice import Notice


def render(notice: Notice) -> bytes:
    image = page_mascot(notice)
    headline, lines, top, matrix = layout(notice, image)
    commands = [f"BT /F1 {headline_size(headline)} Tf {LEFT} {792 - HEADLINE_Y} Td ({literal(headline)}) Tj ET"]
    commands.extend(
        f"BT /F2 10 Tf {LEFT} {792 - y} Td ({literal(line)}) Tj ET" for y, line in lines
    )
    if image:
        height = mascot_height(image)
        commands.append(f"q {MASCOT_WIDTH} 0 0 {height:.3f} "
                        f"{MASCOT_X} {792 - MASCOT_TOP - height:.3f} cm /Mascot Do Q")
    side = QR_WIDTH / len(matrix)
    for y, row in enumerate(matrix):
        for x, dark in enumerate(row):
            if dark:
                commands.append(
                    f"{LEFT + x * side:.4f} {792 - top - (y + 1) * side:.4f} "
                    f"{side:.4f} {side:.4f} re f"
                )
    stream = ("\n".join(commands) + "\n").encode("ascii")
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R "
        b"/Resources << /Font << /F1 5 0 R /F2 6 0 R >>"
        + (b" /XObject << /Mascot 7 0 R >>" if image else b"") + b" >> >>",
        f"<< /Length {len(stream)} >>\nstream\n".encode("ascii") + stream + b"endstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>",
    ]
    if image:
        raster = b"".join(pack_row(row) for row in image)
        objects.append(
            (f"<< /Type /XObject /Subtype /Image /Width {len(image[0])} /Height {len(image)} "
             f"/ImageMask true /BitsPerComponent 1 /Decode [1 0] /Length {len(raster)} >>"
             "\nstream\n").encode("ascii") + raster + b"\nendstream"
        )
    output = bytearray(b"%PDF-1.4\n")
    offsets = []
    for number, obj in enumerate(objects, 1):
        offsets.append(len(output))
        output.extend(f"{number} 0 obj\n".encode("ascii") + obj + b"\nendobj\n")
    xref = len(output)
    count = len(objects) + 1
    output.extend(f"xref\n0 {count}\n0000000000 65535 f \n".encode("ascii"))
    for offset in offsets:
        output.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    output.extend(f"trailer\n<< /Size {count} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode("ascii"))
    return bytes(output)
