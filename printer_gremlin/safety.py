"""Print guardrails: confirmation, volume limits, cooldowns and an audit log.

Hard limits (not overridable from the CLI):
  * one copy per job, at most MAX_PRINTS_PER_RUN jobs per invocation
  * at most one print per target per COOLDOWN_SECONDS, tracked on disk
  * the operator must type the exact target address to confirm
Every print attempt, allowed or refused, is appended to the audit log.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Callable, Optional

MAX_PRINTS_PER_RUN = 3
COOLDOWN_SECONDS = 600
MAX_PAYLOAD_BYTES = 512 * 1024


def state_dir() -> Path:
    base = os.environ.get("PRINTER_GREMLIN_STATE")
    if base:
        p = Path(base)
    elif os.name == "nt":
        p = Path(os.environ.get("LOCALAPPDATA", Path.home())) / "printer-gremlin"
    else:
        p = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state")) / "printer-gremlin"
    p.mkdir(parents=True, exist_ok=True)
    return p


class PrintRefused(RuntimeError):
    pass


class PrintGovernor:
    def __init__(self, now: Callable[[], float] = time.time, directory: Optional[Path] = None):
        self._now = now
        self._dir = directory or state_dir()
        self._history_path = self._dir / "print-history.json"
        self._audit_path = self._dir / "audit.log"
        self._printed_this_run = 0

    # --- persistent history -----------------------------------------
    def _load(self) -> dict:
        try:
            return json.loads(self._history_path.read_text())
        except (FileNotFoundError, ValueError):
            return {}

    def _save(self, data: dict) -> None:
        self._history_path.write_text(json.dumps(data, indent=2))

    def audit(self, event: str, **fields) -> None:
        rec = {"ts": round(self._now(), 3), "event": event, **fields}
        with self._audit_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec) + "\n")

    # --- checks ------------------------------------------------------
    def check(self, target: str, payload_len: int) -> None:
        if self._printed_this_run >= MAX_PRINTS_PER_RUN:
            raise PrintRefused(f"run limit reached ({MAX_PRINTS_PER_RUN} prints per invocation)")
        if payload_len > MAX_PAYLOAD_BYTES:
            raise PrintRefused("payload larger than the notice limit")
        last = self._load().get(target)
        if last is not None:
            wait = COOLDOWN_SECONDS - (self._now() - last)
            if wait > 0:
                raise PrintRefused(
                    f"{target} was printed to {int(self._now() - last)}s ago; "
                    f"cooldown has {int(wait)}s left"
                )

    def record(self, target: str) -> None:
        self._printed_this_run += 1
        data = self._load()
        data[target] = self._now()
        self._save(data)


def confirm(target: str, summary: str, ask: Callable[[str], str] = input) -> bool:
    """Require the operator to type the target address exactly."""
    print(summary)
    answer = ask(f"Type the target address ({target}) to print, or anything else to cancel: ")
    return answer.strip() == target
