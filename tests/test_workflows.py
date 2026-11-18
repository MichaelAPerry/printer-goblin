import json
import socket
from threading import Thread

import pytest

from printer_gremlin import cli, safety, scope, verify
from printer_gremlin.identify import Fingerprint


def test_scope(monkeypatch):
    with pytest.raises(scope.ScopeError):
        scope.resolve_target("8.8.8.8")
    with pytest.raises(scope.ScopeError):
        scope.parse_scan_range("192.168.0.0/21")
    addresses = scope.parse_scan_range("192.168.1.0/24")
    assert len(addresses) == 254
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 0))
    ])
    with pytest.raises(scope.ScopeError):
        scope.resolve_target("printer.example")


def test_governor_limits(tmp_path):
    now = [1000.0]
    governor = safety.PrintGovernor(now=lambda: now[0], directory=tmp_path)
    target = "192.168.1.10"
    governor.check(target, 100)
    governor.record(target)
    with pytest.raises(safety.PrintRefused, match="cooldown"):
        safety.PrintGovernor(now=lambda: now[0], directory=tmp_path).check(target, 100)
    now[0] += safety.COOLDOWN_SECONDS
    governor.check(target, 100)
    for number in range(safety.MAX_PRINTS_PER_RUN - 1):
        other = f"192.168.2.{number + 1}"
        governor.check(other, 100)
        governor.record(other)
    with pytest.raises(safety.PrintRefused, match="run limit"):
        governor.check(target, 100)


def test_verify_localhost(tmp_path, localhost_tcp):
    filename = tmp_path / "baseline.json"
    ip = "127.0.0.1"
    with socket.socket() as listener:
        listener.bind((ip, 0))
        port = listener.getsockname()[1]
        listener.listen()
        saved = verify.baseline([ip], [port], filename, "printer VLAN")
        assert saved["vantage"]["source_ips"][ip] == ip
        report = verify.compare(filename)
        assert report["verdict"] == "FAIL"
        assert report["results"][ip][str(port)]["classification"] == "STILL EXPOSED"
        assert cli.main(["verify", str(filename)]) == 3
    report = verify.compare(filename)
    assert report["verdict"] == "PASS"
    assert report["results"][ip][str(port)]["classification"] == "isolated"
    assert "vantage point" in report["note"]
    previous = verify.baseline([ip], [port], filename, "closed")
    assert previous["results"][ip][str(port)] == "closed"
    assert verify.compare(filename)["results"][ip][str(port)]["classification"] == "unchanged-closed"
    with socket.socket() as listener:
        listener.bind((ip, port))
        listener.listen()
        assert verify.compare(filename)["results"][ip][str(port)]["classification"] == "newly exposed"


def test_demo_refusals(monkeypatch, tmp_path):
    monkeypatch.setenv("PRINTER_GREMLIN_STATE", str(tmp_path))

    def unexpected(*args):
        pytest.fail("refusal should precede identification")

    monkeypatch.setattr(cli, "identify", unexpected)
    assert cli.main(["demo", "127.0.0.1"]) == 1
    assert cli.main(["demo", "8.8.8.8", "--yes-i-am-authorized"]) == 1
    audit = [json.loads(line) for line in (tmp_path / "audit.log").read_text().splitlines()]
    assert [entry["event"] for entry in audit] == ["attempt", "refused", "attempt", "refused"]


def test_demo_unknown_auto(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("PRINTER_GREMLIN_STATE", str(tmp_path))
    monkeypatch.setattr(cli, "identify", Fingerprint)
    assert cli.main(["demo", "127.0.0.1", "--yes-i-am-authorized"]) == 1
    assert "may print garbage pages" in capsys.readouterr().err


def test_preview_is_offline(monkeypatch, tmp_path):
    def unexpected(*args, **kwargs):
        pytest.fail("preview used networking")

    monkeypatch.setattr(socket, "getaddrinfo", unexpected)
    monkeypatch.setattr(socket, "socket", unexpected)
    output = tmp_path / "preview.pdf"
    assert cli.main(["preview", "--format", "pdf", "-o", str(output)]) == 0
    assert output.read_bytes().startswith(b"%PDF-1.4")


def test_demo_one_raw_job(monkeypatch, tmp_path, localhost_tcp):
    ip = "127.0.0.1"
    monkeypatch.setenv("PRINTER_GREMLIN_STATE", str(tmp_path))
    confirmed = []
    monkeypatch.setattr(safety, "confirm", lambda target, summary: not confirmed.append(target))
    jobs = []
    with socket.socket() as listener:
        listener.bind((ip, 0))
        port = listener.getsockname()[1]
        listener.listen()
        listener.settimeout(2)

        def receive_job():
            connection, _ = listener.accept()
            with connection, connection.makefile("rb") as stream:
                jobs.append(stream.read())

        receiver = Thread(target=receive_job)
        receiver.start()
        try:
            assert cli.main(["demo", ip, "--format", "ps", "--port", str(port),
                             "--yes-i-am-authorized"]) == 0
        finally:
            receiver.join()
        listener.setblocking(False)
        with pytest.raises(BlockingIOError):
            listener.accept()
    assert confirmed == [ip]
    assert len(jobs) == 1 and jobs[0].startswith(b"%!PS")
    assert jobs[0].rstrip().endswith(b"showpage")


def test_verify_transitions_without_sockets(monkeypatch, tmp_path):
    from printer_gremlin import net

    ip = "127.0.0.1"
    states = {9100: "open", 631: "open", 515: "closed", 80: "filtered"}
    monkeypatch.setattr(net, "tcp_open", lambda host, port, timeout, accurate=False: states[port])
    monkeypatch.setattr(net, "source_ip", lambda host: ip)
    path = tmp_path / "baseline.json"
    verify.baseline([ip], states, path, "before")
    states.update({9100: "filtered", 515: "open", 80: "closed"})
    report = verify.compare(path)
    assert [report["results"][ip][str(port)]["classification"] for port in states] == [
        "isolated", "STILL EXPOSED", "newly exposed", "unchanged-closed",
    ]
    assert report["verdict"] == "FAIL"
    assert verify.compare(path, ports=[9100])["verdict"] == "PASS"


def test_demo_submits_and_records_one_raw_job_without_sockets(monkeypatch, tmp_path):
    from printer_gremlin import net

    ip = "127.0.0.1"
    actions = []

    class Connection:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            actions.append("close")

        def sendall(self, data):
            assert data.startswith(b"%!PS") and data.rstrip().endswith(b"showpage")
            actions.append("send")

        def shutdown(self, mode):
            assert mode == socket.SHUT_WR
            actions.append("shutdown")

        def settimeout(self, timeout):
            assert timeout <= 0.25

        def recv(self, count):
            actions.append("receive")
            raise socket.timeout

    def connect(address, timeout):
        assert address == (ip, 9100)
        actions.append("connect")
        return Connection()

    def confirm(target, summary):
        assert target == ip and "One notice" in summary
        actions.append("confirm")
        return True

    monkeypatch.setenv("PRINTER_GREMLIN_STATE", str(tmp_path))
    monkeypatch.setattr(cli, "identify", Fingerprint)
    monkeypatch.setattr(net, "source_ip", lambda host: ip)
    monkeypatch.setattr(safety, "confirm", confirm)
    monkeypatch.setattr(socket, "create_connection", connect)
    args = ["demo", ip, "--format", "ps", "--yes-i-am-authorized"]
    assert cli.main(args) == 0
    assert actions == ["confirm", "connect", "send", "shutdown", "receive", "close"]
    assert cli.main(args) == 1
    assert actions.count("connect") == 1
    assert ip in json.loads((tmp_path / "print-history.json").read_text())
