"""QR matrix generation (via segno, pure Python)."""

from __future__ import annotations

from typing import List

import segno


def qr_matrix(data: str, border: int = 2) -> List[List[bool]]:
    """Return rows of booleans (True = dark module), including a quiet zone."""
    qr = segno.make(data, error="m", micro=False)
    return [[bool(v) for v in row] for row in qr.matrix_iter(scale=1, border=border)]


def scale_matrix(m: List[List[bool]], factor: int) -> List[List[bool]]:
    out = []
    for row in m:
        wide = [v for v in row for _ in range(factor)]
        out.extend([list(wide) for _ in range(factor)])
    return out
