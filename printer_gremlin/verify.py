"""Record and compare TCP reachability from the current network vantage."""

from __future__ import annotations

import json
import socket
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address
from pathlib import Path
from typing import Iterable, Optional, Union

from . import net, scope

_STATES = {"open", "closed", "filtered"}
EXIT_CODES = {"PASS": 0, "EXPOSED": 3, "INCONCLUSIVE": 4, "OVER-BLOCKED": 5}
_EXPLANATIONS = {
    "PASS": "All selected ports match the baseline policy.",
    "EXPOSED": "At least one port expected to be denied is open.",
    "OVER-BLOCKED": "At least one port expected to stay reachable is unavailable.",
    "INCONCLUSIVE": ("The printer may be offline; run a reference snapshot from an "
                     "allowed network or pass --printer-online."),
}


def _vantage(targets: Iterable[str]) -> dict:
    return {
        "hostname": socket.gethostname(),
        "source_ips": {ip: net.source_ip(ip) for ip in targets},
        "behind_wsl_nat": net._is_wsl(),
    }


def _probe(pairs: Iterable[tuple[str, int]], targets: Iterable[str]) -> dict[str, dict[str, str]]:
    results: dict[str, dict[str, str]] = {ip: {} for ip in targets}
    for (ip, port), state in net.probe_with_retry(list(pairs), 0.8, accurate=True).items():
        results[ip][str(port)] = state
    return results


def baseline(targets: list[str], ports: Iterable[int], out_path: Union[str, Path], label: str,
             *, expect: str = "deny", allow: Iterable[int] = (), reference: bool = False) -> dict:
    """Save reachability and the policy for this network vantage."""
    ports = tuple(dict.fromkeys(ports))
    if not targets or not ports or any(type(port) is not int or not 1 <= port <= 65535 for port in ports):
        raise ValueError("baseline requires targets and ports in 1..65535")
    allowed = set(allow)
    if expect != "deny":
        raise ValueError("The default baseline policy must be deny.")
    if not allowed.issubset(ports):
        raise ValueError("Allowed ports must be included in the baseline ports.")
    ips = list(dict.fromkeys(str(scope.resolve_target(target)) for target in targets))
    report = {
        "label": label,
        "created": datetime.now(timezone.utc).isoformat(),
        "vantage": _vantage(ips),
        "policy": {str(port): "allow" if port in allowed else expect for port in ports},
        "results": _probe(((ip, port) for ip in ips for port in ports), ips),
    }
    if reference:
        report["reference"] = True
    Path(out_path).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


def _read_results(report: dict) -> dict:
    if not isinstance(report, dict) or not isinstance(report.get("results"), dict):
        raise ValueError("Invalid reachability results.")
    for ip, states in report["results"].items():
        # Snapshot addresses are data, not hostnames to resolve.
        try:
            address = ip_address(ip)
        except ValueError as exc:
            raise ValueError("Results must be keyed by canonical IP.") from exc
        if str(address) != ip or not isinstance(states, dict):
            raise ValueError("Results must be keyed by canonical IP.")
        for port, state in states.items():
            number = int(port)
            if str(number) != port or not 1 <= number <= 65535 or not isinstance(state, str) or state not in _STATES:
                raise ValueError("Invalid port or reachability state.")
    return report["results"]


def _check_reference(reference: dict, targets: Iterable[str], now: datetime) -> None:
    results = _read_results(reference)
    if reference.get("reference") is not True:
        raise ValueError("Use a reference file created with the snapshot command.")
    try:
        created = datetime.fromisoformat(reference.get("created", "").replace("Z", "+00:00"))
        age = now - created
    except (TypeError, ValueError, AttributeError) as exc:
        raise ValueError("Reference snapshot needs a valid timestamp with a time zone.") from exc
    if not timedelta(0) <= age <= timedelta(minutes=30):
        raise ValueError("Reference snapshot must be no more than 30 minutes old and dated in the past.")
    for ip in targets:
        if "open" not in results.get(ip, {}).values():
            raise ValueError(f"Reference snapshot must show at least one open port for {ip}.")


def _classify(policy: str, after: str, live: bool) -> str:
    if policy == "allow":
        return "OK" if after == "open" else "OVER-BLOCKED"
    if after == "open":
        return "EXPOSED"
    return "BLOCKED" if after == "closed" or live else "UNVERIFIED"


def compare(baseline_path: Union[str, Path], ports: Optional[Iterable[int]] = None, *,
            reference: Optional[Union[str, Path, dict]] = None, printer_online: bool = False) -> dict:
    """Re-probe stored endpoints and compare reachability with the saved policy."""
    now = datetime.now(timezone.utc)
    old = json.loads(Path(baseline_path).read_text(encoding="utf-8"))
    saved = _read_results(old)
    policy = old.get("policy", {})
    if not isinstance(policy, dict) or any(value not in ("allow", "deny") for value in policy.values()):
        raise ValueError("Invalid baseline policy.")
    selected = None if ports is None else set(ports)
    previous = {}
    pairs = []
    for ip, states in saved.items():
        scope.resolve_target(ip)
        for port, state in states.items():
            if selected is None or int(port) in selected:
                previous.setdefault(ip, {})[port] = state
                pairs.append((ip, int(port)))
    if not pairs:
        raise ValueError("No baseline endpoints selected.")
    if reference is not None:
        if not isinstance(reference, dict):
            reference = json.loads(Path(reference).read_text(encoding="utf-8"))
        _check_reference(reference, previous, now)

    current = _probe(pairs, previous)
    results = {}
    liveness = {}
    for ip, states in previous.items():
        evidence = []
        if reference is not None:
            evidence.append("reference-snapshot")
        if any(state in ("open", "closed") for state in current[ip].values()):
            evidence.append("verify-response")
        if printer_online:
            evidence.append("operator-asserted")
        liveness[ip] = evidence
        results[ip] = {}
        for port, before in states.items():
            after = current[ip][port]
            expectation = policy.get(port, "deny")
            results[ip][port] = {
                "before": before, "after": after, "policy": expectation,
                "classification": _classify(expectation, after, bool(evidence)),
            }
    classifications = {row["classification"] for states in results.values() for row in states.values()}
    verdict = "PASS"
    for outcome, classification in (("EXPOSED", "EXPOSED"), ("OVER-BLOCKED", "OVER-BLOCKED"),
                                    ("INCONCLUSIVE", "UNVERIFIED")):
        if classification in classifications:
            verdict = outcome
            break
    return {
        "label": old.get("label"),
        "baseline_vantage": old.get("vantage"),
        "vantage": _vantage(previous),
        "results": results,
        "liveness": liveness,
        "verdict": verdict,
        "explanation": _EXPLANATIONS[verdict],
        "note": "Results apply only to the network vantage point they were run from.",
        "liveness_note": ("Operator-asserted liveness is weaker than a network response."
                          if printer_online else None),
    }
