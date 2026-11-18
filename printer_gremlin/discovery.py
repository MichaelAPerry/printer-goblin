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
    hosts = {}
    for ip, port, state in net.probe_many(
        ((str(ip), port) for ip in addresses for port in ports), timeout
    ):
        if state == "open":
            hosts.setdefault(ip, Host(ip)).open_ports.append(port)
    return list(hosts.values())
