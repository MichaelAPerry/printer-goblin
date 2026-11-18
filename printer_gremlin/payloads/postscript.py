"""Render one notice as self-contained PostScript."""

from ._page import HEADLINE_Y, LEFT, QR_WIDTH, headline_size, layout, literal
from .notice import Notice


def render(notice: Notice) -> bytes:
    headline, lines, top, matrix = layout(notice)
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
