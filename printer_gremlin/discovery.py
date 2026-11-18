"""Discover hosts with open printer-related TCP ports."""

from dataclasses import dataclass, field
from typing import Iterable

from . import net, scope

DEFAULT_PORTS = (9100, 631, 515, 80, 443)


@dataclass
class Host:
    ip: str
    open_ports: list[int] = field(default_factory=list)


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
