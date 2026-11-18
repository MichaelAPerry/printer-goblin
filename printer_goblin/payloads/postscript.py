"""Render one notice as self-contained PostScript."""

from ..assets import pack_row
from ._page import (HEADLINE_Y, LEFT, MASCOT_TOP, MASCOT_WIDTH, MASCOT_X, QR_WIDTH,
                    headline_size, layout, mascot_height, page_mascot, literal)
from .notice import Notice


def render(notice: Notice) -> bytes:
    image = page_mascot(notice)
    headline, lines, top, matrix = layout(notice, image)
    commands = [
        "%!PS-Adobe-3.0",
        "%%Pages: 1",
        "%%EndComments",
        "%%Page: 1 1",
        "<< /NumCopies 1 >> setpagedevice",
        "/pageheight currentpagedevice /PageSize get 1 get def",
        f"/Helvetica-Bold findfont {headline_size(headline)} scalefont setfont",
        f"{LEFT} pageheight {HEADLINE_Y} sub moveto ({literal(headline)}) show",
        "/Courier findfont 10 scalefont setfont",
    ]
    if image:
        width, height = len(image[0]), len(image)
        hex_rows = "\n".join(pack_row(row).hex() for row in image)
        commands.extend([
            "gsave",
            f"{MASCOT_X} pageheight {MASCOT_TOP + mascot_height(image):.3f} sub translate",
            f"{MASCOT_WIDTH} {mascot_height(image):.3f} scale",
            f"{width} {height} true [{width} 0 0 -{height} 0 {height}]",
            f"{{ currentfile {len(pack_row(image[0]))} string readhexstring pop }} imagemask",
            hex_rows, "grestore",
        ])
    commands.extend(f"{LEFT} pageheight {y} sub moveto ({literal(line)}) show" for y, line in lines)
    side = QR_WIDTH / len(matrix)
    for y, row in enumerate(matrix):
        for x, dark in enumerate(row):
            if dark:
                commands.append(
                    f"{LEFT + x * side:.4f} pageheight {top + (y + 1) * side:.4f} sub "
                    f"{side:.4f} {side:.4f} rectfill"
                )
    commands.append("showpage")
    return ("\n".join(commands) + "\n").encode("ascii")
