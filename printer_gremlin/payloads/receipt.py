"""Render a wrapped notice using the allowlisted ESC/POS builder."""

import textwrap

from .escpos import EscPosJob
from .notice import Notice
from .qr import qr_matrix, scale_matrix


def render(notice: Notice, width_chars: int = 32, native_qr: bool = True) -> bytes:
    if width_chars < 2:
        raise ValueError("receipt must be at least two columns wide")
    job = EscPosJob().init().align("center").bold(True).size(2, 2)

    def add_line(line: str, width: int) -> None:
        clean = "".join(char if 32 <= ord(char) < 127 else "?" for char in line)
        for part in textwrap.wrap(clean, width, break_on_hyphens=False) or [""]:
            job.line(part)

    add_line(notice.headline, width_chars // 2)
    job.size().bold(False).align("left")
    for line in notice.lines:
        add_line(line, width_chars)
    job.align("center").line()
    matrix = qr_matrix(notice.url, border=4)
    if native_qr:
        # At 12 dots per text column, leave room for the QR quiet zone.
        module_size = max(1, min(6, width_chars * 12 // len(matrix)))
        if not notice.url.isascii() or not notice.url.isprintable():
            raise ValueError("native receipt QR requires a printable ASCII URL")
        job.qr_native(notice.url, module_size).line()
    else:
        job.raster(scale_matrix(matrix, 4)).line()
    add_line(notice.url, width_chars)
    for line in notice.footer:
        add_line(line, width_chars)
    return job.feed(4).cut().to_bytes()
