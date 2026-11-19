"""Scope guardrails: what Printer Goblin is allowed to touch.

Policy (deliberately strict, not configurable from the CLI):
  * Only private (RFC 1918), shared CGNAT (RFC 6598), link-local and IPv6
    unique-local/link-local addresses are in scope. Public addresses are
    refused for both scanning and printing.
  * A single scan may cover at most MAX_SCAN_HOSTS addresses (a /16). Anything
    bigger would take days at the paced probe rate; scan it one /16 at a time.
    Scans over LARGE_SCAN_HOSTS (a /22) come with a time estimate and a warning.
  * Hostnames are resolved once and the resolved address must pass the
    same checks, so DNS cannot be used to smuggle in a public target.
"""

from __future__ import annotations

import ipaddress
import socket
from typing import List, Union

MAX_SCAN_HOSTS = 65536
LARGE_SCAN_HOSTS = 1024

IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
IPNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]

_ALLOWED_NETS = [
    ipaddress.ip_network(n)
    for n in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "100.64.0.0/10",  # RFC 6598 shared address space (common in labs)
        "169.254.0.0/16",
        "fc00::/7",
        "fe80::/10",
    )
]


class ScopeError(ValueError):
    """Raised when a target or range falls outside the permitted scope."""


def is_in_scope(addr: IPAddress) -> bool:
    if addr.is_loopback:
        return True  # useful for local emulators and tests
    if addr.is_multicast or addr.is_unspecified or addr.is_reserved:
        return False
    return any(addr in net for net in _ALLOWED_NETS)


def resolve_target(target: str) -> IPAddress:
    """Resolve a single print/identify target and enforce scope."""
    try:
        addr = ipaddress.ip_address(target)
    except ValueError:
        try:
            info = socket.getaddrinfo(target, None, proto=socket.IPPROTO_TCP)
        except socket.gaierror as exc:
            raise ScopeError(f"cannot resolve {target!r}: {exc}") from exc
        addr = ipaddress.ip_address(info[0][4][0].split("%")[0])
    if not is_in_scope(addr):
        raise ScopeError(
            f"{target} ({addr}) is not a private/link-local address. "
            "Printer Goblin only operates on internal networks."
        )
    return addr


def scan_network(cidr: str) -> IPNetwork:
    """Parse a CIDR for scanning, enforcing scope and the size ceiling."""
    try:
        net: IPNetwork = ipaddress.ip_network(cidr, strict=False)
    except ValueError as exc:
        raise ScopeError(f"invalid network {cidr!r}: {exc}") from exc
    if net.num_addresses > MAX_SCAN_HOSTS:
        raise ScopeError(
            f"{cidr} has {net.num_addresses:,} addresses; one scan covers at most a /16 "
            f"({MAX_SCAN_HOSTS:,}), which already takes over an hour. Scan it one /16 at a time."
        )
    if not (is_in_scope(net.network_address) and is_in_scope(net.broadcast_address)):
        raise ScopeError(f"{cidr} is not entirely inside private/link-local space.")
    return net


def scan_host_count(cidr: str) -> int:
    net = scan_network(cidr)
    return net.num_addresses - 2 if net.num_addresses > 2 else net.num_addresses


def parse_scan_range(cidr: str) -> List[IPAddress]:
    """Expand a CIDR for scanning, enforcing scope and size limits."""
    net = scan_network(cidr)
    return list(net.hosts()) if net.num_addresses > 2 else list(net)
