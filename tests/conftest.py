import errno
import socket

import pytest


@pytest.fixture
def localhost_tcp():
    """Run live TCP tests only when the runner permits loopback sockets."""
    try:
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
    except OSError as exc:
        if exc.errno in (errno.EPERM, errno.EACCES):
            pytest.skip("runner blocks localhost TCP sockets")
        raise
