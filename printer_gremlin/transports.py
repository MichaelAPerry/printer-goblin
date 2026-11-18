"""One-shot transports for a rendered notice."""

import socket
from typing import Optional

from .protocols import ipp
from .scope import resolve_target


def send_raw(host: str, data: bytes, port: int = 9100, timeout: float = 10) -> None:
    """Submit one raw job, then briefly drain the printer response."""
    host = str(resolve_target(host))
    with socket.create_connection((host, port), timeout) as connection:
        connection.sendall(data)
        connection.shutdown(socket.SHUT_WR)
        connection.settimeout(min(timeout, 0.25))
        try:
            connection.recv(4096)
        except (socket.timeout, ConnectionResetError):
            pass


def send_ipp(host: str, data: bytes, document_format: str, port: int = 631,
             path: str = "/ipp/print", job_name: str = "Printer Gremlin notice",
             timeout: float = 10, *, tls: bool = False) -> tuple[int, Optional[int]]:
    """Submit one IPP job and return its status and job ID."""
    return ipp.print_job(host, data, document_format, port, path, job_name, timeout, tls=tls)
