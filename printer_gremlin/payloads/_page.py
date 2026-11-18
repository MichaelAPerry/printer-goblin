"""Shared US Letter and A4 notice layout, in points from the top left."""

from __future__ import annotations

import textwrap

from .notice import Notice
from .qr import qr_matrix

LEFT = 36
HEADLINE_Y = 58
QR_WIDTH = 115.2
LINE_HEIGHT = 13


def clean_text(value: str) -> str:
    return "".join(char if 32 <= ord(char) < 127 else "?" for char in value)


def literal(value: str) -> str:
    """Escape a printable string for PostScript and PDF."""
    return value.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def headline_size(headline: str) -> int:
    """Keep even a headline of wide characters within the text box."""
    return min(24, 504 // max(1, len(headline)))


def layout(notice: Notice) -> tuple[str, list[tuple[int, str]], int, list[list[bool]]]:
    """Return headline, positioned lines, and the QR's top and matrix."""
    headline = clean_text(notice.headline)
    if len(headline) > 36:
        raise ValueError("notice headline is too wide")
    lines = []
    y = 86

    def add_lines(values: list[str]) -> None:
        nonlocal y
        for value in values:
            for line in textwrap.wrap(clean_text(value), width=84, break_on_hyphens=False) or [""]:
                lines.append((y, line))
                y += LINE_HEIGHT

    add_lines(notice.lines)
    qr_top = y
    y += 134
    add_lines([notice.url])
    y += 8
    add_lines(notice.footer)
    if y > 720:
        raise ValueError("notice does not fit on one page")
    return headline, lines, qr_top, qr_matrix(notice.url, border=4)
