"""Discover hosts with open printer-related TCP ports."""

from dataclasses import dataclass, field
from typing import Iterable

from . import net, scope

DEFAULT_PORTS = (9100, 631, 515, 80, 443)


@dataclass
class Host:
    ip: str
    open_ports: list[int] = field(default_factory=list)


def _duration(seconds: float) -> str:
    if seconds < 90:
        return f"{max(1, round(seconds))} seconds"
    if seconds < 90 * 60:
        return f"{round(seconds / 60)} minutes"
    return f"{seconds / 3600:.1f} hours"


def scan_estimate(cidr: str, ports: Iterable[int] = DEFAULT_PORTS, timeout: float = 0.8) -> dict:
    """Worst-case time for the port sweep, and a warning for large ranges.

    Most of a big sweep is waiting on addresses that never answer, so the
    estimate assumes every probe times out; real scans usually finish sooner.
    """
    hosts = scope.scan_host_count(cidr)
    port_count = len(dict.fromkeys(ports))
    rate = min(net.PROBE_RATE, net.MAX_WORKERS / timeout)
    seconds = hosts * port_count / rate
    large = hosts > scope.LARGE_SCAN_HOSTS
    message = (f"{cidr}: {hosts:,} addresses x {port_count} ports. "
               f"Estimated time: up to about {_duration(seconds)} for the sweep, "
               "plus a few seconds for each printer found.")
    if large:
        message += (" Extensive scans generate significant noise and may trigger "
                    "intrusion-detection alerts. Verify that the network owner has anticipated this activity.")
    return {"cidr": cidr, "hosts": hosts, "ports": port_count, "seconds": round(seconds),
            "large": large, "message": message}


def discover(cidr: str, ports: Iterable[int] = DEFAULT_PORTS,
             timeout: float = 0.8) -> list[Host]:
    addresses = scope.parse_scan_range(cidr)
    ports = tuple(dict.fromkeys(ports))
    pairs = [(str(ip), port) for ip in addresses for port in ports]
    states = {(h, p): st for h, p, st in net.probe_many(pairs, timeout)}
    # Second, slower pass only for hosts that answered at all (a sleeping
    # printer may answer one port fast and the rest slowly).
    alive = {h for (h, _), st in states.items() if st in ("open", "closed")}
    slow = [pair for pair in pairs if pair[0] in alive and states[pair] == "filtered"]
    for h, p, st in net.probe_many(slow, max(timeout, net.SLOW_RETRY_TIMEOUT)):
        states[(h, p)] = st
    hosts = {}
    for ip, port in pairs:
        if states[(ip, port)] == "open":
            hosts.setdefault(ip, Host(ip)).open_ports.append(port)
    return list(hosts.values())
