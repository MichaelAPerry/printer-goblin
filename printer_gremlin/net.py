"""Bounded TCP connect probes."""

from __future__ import annotations

import errno
import socket
import threading
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from itertools import islice
from typing import Iterable, Iterator


def tcp_open(host: str, port: int, timeout: float) -> str:
    """Classify a TCP connect without sending data."""
    try:
        with socket.create_connection((host, port), timeout):
            return "open"
    except OSError as exc:
        return "closed" if exc.errno == errno.ECONNREFUSED else "filtered"


_probe_lock = threading.Lock()
_next_probe = 0.0


def probe_many(
    pairs: Iterable[tuple[str, int]], timeout: float, workers: int = 64
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
        return host, port, tcp_open(host, port, timeout)

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


def source_ip(target: str) -> str:
    """Ask the routing table for the source address without sending a packet."""
    family = socket.AF_INET6 if ":" in target else socket.AF_INET
    try:
        with socket.socket(family, socket.SOCK_DGRAM) as sock:
            sock.connect((target, 9))
            return sock.getsockname()[0]
    except OSError:
        return "unknown"
