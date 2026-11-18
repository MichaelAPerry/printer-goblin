"""Record and compare TCP reachability from the current network vantage."""

from __future__ import annotations

import json
import socket
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Optional, Union

from . import net, scope

_STATES = {"open", "closed", "filtered"}


def _vantage(targets: Iterable[str]) -> dict:
    return {
        "hostname": socket.gethostname(),
        "source_ips": {ip: net.source_ip(ip) for ip in targets},
    }


def _probe(pairs: Iterable[tuple[str, int]], targets: Iterable[str]) -> dict[str, dict[str, str]]:
    results: dict[str, dict[str, str]] = {ip: {} for ip in targets}
    for ip, port, state in net.probe_many(pairs, 0.8):
        results[ip][str(port)] = state
    return results


def baseline(targets: list[str], ports: Iterable[int], out_path: Union[str, Path], label: str) -> dict:
    """Save the current reachability of the selected targets and ports."""
    ips = list(dict.fromkeys(str(scope.resolve_target(target)) for target in targets))
    ports = tuple(dict.fromkeys(ports))
    if not ips or not ports or any(type(port) is not int or not 1 <= port <= 65535 for port in ports):
        raise ValueError("baseline requires targets and ports in 1..65535")
    report = {
        "label": label,
        "created": datetime.now(timezone.utc).isoformat(),
        "vantage": _vantage(ips),
        "results": _probe(((ip, port) for ip in ips for port in ports), ips),
    }
    Path(out_path).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


def _classify(before: str, after: str) -> str:
    if after == "open":
        return "STILL EXPOSED" if before == "open" else "newly exposed"
    return "isolated" if before == "open" else "unchanged-closed"


def compare(baseline_path: Union[str, Path], ports: Optional[Iterable[int]] = None) -> dict:
    """Re-probe stored endpoints and classify changes in reachability."""
    old = json.loads(Path(baseline_path).read_text(encoding="utf-8"))
    if not isinstance(old, dict) or not isinstance(old.get("results"), dict):
        raise ValueError("invalid baseline results")
    selected = None if ports is None else set(ports)
    previous: dict[str, dict[str, str]] = {}
    pairs = []
    for target, states in old["results"].items():
        ip = str(scope.resolve_target(target))
        if ip != target or not isinstance(states, dict):
            raise ValueError("baseline results must be keyed by canonical IP")
        previous[ip] = {}
        for port, state in states.items():
            number = int(port)
            if str(number) != port or not 1 <= number <= 65535 or not isinstance(state, str) or state not in _STATES:
                raise ValueError("invalid baseline port or state")
            if selected is None or number in selected:
                previous[ip][port] = state
                pairs.append((ip, number))
    if not pairs:
        raise ValueError("no baseline endpoints selected")
    current = _probe(pairs, previous)
    results = {
        ip: {port: {"before": before, "after": current[ip][port],
                    "classification": _classify(before, current[ip][port])}
             for port, before in states.items()}
        for ip, states in previous.items()
    }
    exposed = any(state == "open" for states in current.values() for state in states.values())
    return {
        "label": old.get("label"),
        "baseline_vantage": old.get("vantage"),
        "vantage": _vantage(previous),
        "results": results,
        "verdict": "FAIL" if exposed else "PASS",
        "note": "Results apply only to the network vantage point they were run from.",
    }
