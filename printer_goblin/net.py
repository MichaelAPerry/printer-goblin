"""Bounded TCP connect probes."""

from __future__ import annotations

import errno
import ipaddress
import socket
import sys
import threading
import time
from collections import deque
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor
from itertools import islice
from typing import Iterable, Iterator


# Windows retries a refused SYN for ~2 s before reporting ECONNREFUSED, so a
# shorter timeout would mislabel closed ports as "filtered". Callers that need
# the closed/filtered distinction (verify) pass accurate=True.
WINDOWS_REFUSED_DELAY = 2.5


# Test/demo hook: (host, logical port) -> actual port. Empty in normal use.
# Overrides are only ever accepted for loopback hosts, so a real network
# target can never be redirected.
PORT_OVERRIDES: dict[tuple[str, int], int] = {}


def _check_loopback(host: str) -> None:
    assert ipaddress.ip_address(host.split("%")[0]).is_loopback, \
        f"port overrides are loopback-only, got {host!r}"


def actual_port(host: str, port: int) -> int:
    """Port to really connect to for a logical printer port (identity by default)."""
    if (host, port) in PORT_OVERRIDES:
        _check_loopback(host)
        return PORT_OVERRIDES[(host, port)]
    return port


@contextmanager
def port_overrides(mapping: dict[int, int], host: str = "127.0.0.1"):
    """Temporarily map logical ports to actual ones for a loopback host."""
    _check_loopback(host)
    keys = [(host, logical) for logical in mapping]
    saved = {key: PORT_OVERRIDES[key] for key in keys if key in PORT_OVERRIDES}
    PORT_OVERRIDES.update({(host, logical): actual for logical, actual in mapping.items()})
    try:
        yield
    finally:
        for key in keys:
            PORT_OVERRIDES.pop(key, None)
        PORT_OVERRIDES.update(saved)


def tcp_open(host: str, port: int, timeout: float, accurate: bool = False) -> str:
    """Classify a TCP connect without sending data."""
    if accurate and sys.platform == "win32":
        timeout = max(timeout, WINDOWS_REFUSED_DELAY)
    try:
        with socket.create_connection((host, actual_port(host, port)), timeout):
            return "open"
    except OSError as exc:
        return "closed" if exc.errno == errno.ECONNREFUSED else "filtered"


_probe_lock = threading.Lock()
_next_probe = 0.0


def probe_many(
    pairs: Iterable[tuple[str, int]], timeout: float, workers: int = 64,
    accurate: bool = False,
) -> Iterator[tuple[str, int, str]]:
    """Probe up to 64 pairs concurrently, pacing starts across callers."""
    def probe(pair: tuple[str, int]) -> tuple[str, int, str]:
        global _next_probe
        with _probe_lock:
            delay = _next_probe - time.monotonic()
            if delay > 0:
                time.sleep(delay)
            _next_probe = time.monotonic() + 1 / 200
        host, port = pair
        return host, port, tcp_open(host, port, timeout, accurate)

    limit = max(1, min(64, workers))
    remaining = iter(pairs)
    with ThreadPoolExecutor(max_workers=limit) as pool:
        pending = deque(pool.submit(probe, pair) for pair in islice(remaining, limit))
        while pending:
            result = pending.popleft().result()
            pair = next(remaining, None)
            if pair is not None:
                pending.append(pool.submit(probe, pair))
            yield result


SLOW_RETRY_TIMEOUT = 3.0


def probe_with_retry(pairs: Iterable[tuple[str, int]], timeout: float,
                     accurate: bool = False,
                     retry_if=lambda host, port: True) -> dict[tuple[str, int], str]:
    """Probe, then re-probe "filtered" results once with a longer timeout.

    Printers waking from deep sleep (or busy printing) can take seconds to
    answer, which a short first-pass timeout reports as "filtered".
    retry_if(host, port) limits the second pass, e.g. to hosts known to be up.
    """
    states = {(h, p): st for h, p, st in probe_many(pairs, timeout, accurate=accurate)}
    again = [pair for pair, st in states.items() if st == "filtered" and retry_if(*pair)]
    for h, p, st in probe_many(again, max(timeout, SLOW_RETRY_TIMEOUT), accurate=accurate):
        states[(h, p)] = st
    return states


def source_ip(target: str) -> str:
    """Ask the routing table for the source address without sending a packet."""
    family = socket.AF_INET6 if ":" in target else socket.AF_INET
    try:
        with socket.socket(family, socket.SOCK_DGRAM) as sock:
            sock.connect((target, 9))
            return sock.getsockname()[0]
    except OSError:
        return "unknown"


def _is_wsl() -> bool:
    try:
        with open("/proc/version", encoding="utf-8") as fh:
            return "microsoft" in fh.read().lower()
    except OSError:
        return False


def source_label(target: str) -> str:
    """Human-readable vantage point for the printout.

    The local address can differ from what the printer sees when this host is
    behind NAT (WSL2, containers, VMs), so say so instead of implying otherwise.
    """
    label = f"{socket.gethostname()} ({source_ip(target)})"
    if _is_wsl():
        label += " via WSL NAT"
    return label
