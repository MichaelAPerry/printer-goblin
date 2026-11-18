"""The content of the printed notice, independent of printer language."""

from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass, field
from typing import List

DEFAULT_GUIDE_URL = "https://michaelaperry.github.io/printer-goblin/"


@dataclass
class Notice:
    headline: str
    lines: List[str]
    url: str
    footer: List[str] = field(default_factory=list)


def build_notice(target: str, port: int, protocol: str, source: str,
                 guide_url: str = DEFAULT_GUIDE_URL, note: str = "",
                 when: _dt.datetime = None) -> Notice:
    when = when or _dt.datetime.now().astimezone()
    lines = list(NOTICE_BODY)
    facts = [
        f"Printer:  {target}:{port} ({protocol})",
        f"Reached from: {source}",
        f"Time: {when.strftime('%Y-%m-%d %H:%M %Z')}",
    ]
    if note:
        facts.append(f"Assessor: {note[:60]}")
    return Notice(headline=HEADLINE, lines=lines + [""] + facts, url=guide_url,
                  footer=list(FOOTER))


# Wording is kept short so it fits a 32-column receipt.
HEADLINE = "YOU'VE BEEN GOBBED!"
# Drafted by the local wording model (qwen3.5:9b); line 4 corrected for
# accuracy (printers usually keep a job-log entry, so "nothing saved" is untrue).
NOTICE_BODY: List[str] = [
    "A gremlin just grabbed a page here!",
    "It came from a network that shouldn't reach us.",
    "This was an authorized security test, not a hack.",
    "No settings were changed and nothing was taken.",
    "Please hand this sheet to your IT or Security team.",
    "We are checking our printer protection right now.",
]
FOOTER: List[str] = [
    "Scan the QR code to learn how we will fix it.",
    "-- Printer Gremlin",
]
