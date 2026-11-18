"""Scope guardrails: what Printer Gremlin is allowed to touch.

Policy (deliberately strict, not configurable from the CLI):
  * Only private (RFC 1918), shared CGNAT (RFC 6598), link-local and IPv6
    unique-local/link-local addresses are in scope. Public addresses are
    refused for both scanning and printing.
  * A single scan may cover at most MAX_SCAN_HOSTS addresses (a /22).
  * Hostnames are resolved once and the resolved address must pass the
    same checks, so DNS cannot be used to smuggle in a public target.
"""

from __future__ import annotations

import ipaddress
import socket
from typing import List, Union

MAX_SCAN_HOSTS = 1024

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
            "Printer Gremlin only operates on internal networks."
        )
    return addr


def parse_scan_range(cidr: str) -> List[IPAddress]:
    """Expand a CIDR for scanning, enforcing scope and size limits."""
    try:
        net: IPNetwork = ipaddress.ip_network(cidr, strict=False)
    except ValueError as exc:
        raise ScopeError(f"invalid network {cidr!r}: {exc}") from exc
    if net.num_addresses > MAX_SCAN_HOSTS + 2:
        raise ScopeError(
            f"{cidr} has {net.num_addresses} addresses; the limit is "
            f"{MAX_SCAN_HOSTS} (a /22). Split the range or narrow it."
        )
    if not (is_in_scope(net.network_address) and is_in_scope(net.broadcast_address)):
        raise ScopeError(f"{cidr} is not entirely inside private/link-local space.")
    hosts = list(net.hosts()) if net.num_addresses > 2 else list(net)
    return hosts
