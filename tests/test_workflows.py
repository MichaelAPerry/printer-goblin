import json
import socket
from threading import Thread

import pytest

from printer_goblin import cli, safety, scope, verify
from printer_goblin.identify import Fingerprint
from printer_goblin.payloads import pjl


def test_scope(monkeypatch):
    with pytest.raises(scope.ScopeError):
        scope.resolve_target("8.8.8.8")
    with pytest.raises(scope.ScopeError, match="one /16 at a time"):
        scope.parse_scan_range("10.0.0.0/15")
    with pytest.raises(scope.ScopeError):
        scope.parse_scan_range("8.8.0.0/16")
    assert scope.scan_host_count("10.20.0.0/16") == 65534
    assert len(scope.parse_scan_range("192.168.0.0/21")) == 2046
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
        assert report["verdict"] == "EXPOSED"
        assert report["results"][ip][str(port)]["classification"] == "EXPOSED"
        assert cli.main(["verify", str(filename)]) == 3
    report = verify.compare(filename)
    assert report["verdict"] == "PASS"
    assert report["results"][ip][str(port)]["classification"] == "BLOCKED"
    assert "vantage point" in report["note"]
    previous = verify.baseline([ip], [port], filename, "closed")
    assert previous["results"][ip][str(port)] == "closed"
    assert verify.compare(filename)["results"][ip][str(port)]["classification"] == "BLOCKED"
    with socket.socket() as listener:
        listener.bind((ip, port))
        listener.listen()
        assert verify.compare(filename)["results"][ip][str(port)]["classification"] == "EXPOSED"


def test_demo_refusals(monkeypatch, tmp_path):
    monkeypatch.setenv("PRINTER_GOBLIN_STATE", str(tmp_path))

    def unexpected(*args):
        pytest.fail("refusal should precede identification")

    monkeypatch.setattr(cli, "identify", unexpected)
    assert cli.main(["demo", "127.0.0.1"]) == 1
    assert cli.main(["demo", "8.8.8.8", "--yes-i-am-authorized"]) == 1
    audit = [json.loads(line) for line in (tmp_path / "audit.log").read_text().splitlines()]
    assert [entry["event"] for entry in audit] == ["attempt", "refused", "attempt", "refused"]


def test_demo_unknown_auto(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("PRINTER_GOBLIN_STATE", str(tmp_path))
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
    monkeypatch.setenv("PRINTER_GOBLIN_STATE", str(tmp_path))
    confirmed = []
    monkeypatch.setattr(safety, "confirm", lambda target, summary: not confirmed.append(target))
    jobs = []
    with socket.socket() as listener:
        listener.bind((ip, 0))
        port = listener.getsockname()[1]
        listener.listen()
        listener.settimeout(20)  # identify runs first; refused probes are slow on Windows

        def receive_job():
            # Reachability probes (connect, then close) may arrive before the job itself.
            while not jobs:
                connection, _ = listener.accept()
                with connection, connection.makefile("rb") as stream:
                    data = stream.read()
                if data:
                    jobs.append(data)

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
    assert len(jobs) == 1 and jobs[0].startswith(pjl.UEL + b"@PJL JOB") and b"ENTER LANGUAGE = POSTSCRIPT\r\n%!PS" in jobs[0]
    assert jobs[0].endswith(pjl.UEL) and jobs[0].split(pjl.UEL + b"@PJL EOJ")[0].rstrip().endswith(b"showpage")


@pytest.mark.parametrize("states,allowed,classes,verdict,code", [
    (("open", "closed"), (631,), ("EXPOSED", "OVER-BLOCKED"), "EXPOSED", 3),
    (("filtered", "open"), (631,), ("BLOCKED", "OK"), "PASS", 0),
    (("filtered", "closed"), (), ("BLOCKED", "BLOCKED"), "PASS", 0),
    (("filtered", "filtered"), (), ("UNVERIFIED", "UNVERIFIED"), "INCONCLUSIVE", 4),
    (("filtered", "filtered"), (631,), ("UNVERIFIED", "OVER-BLOCKED"), "OVER-BLOCKED", 5),
])
def test_verify_policy_and_exit_codes(monkeypatch, tmp_path, capsys, states, allowed, classes, verdict, code):
    from printer_goblin import net

    ip = "127.0.0.1"
    ports = (9100, 631)
    results = dict(zip(ports, states))
    monkeypatch.setattr(net, "tcp_open", lambda host, port, timeout, accurate=False: results[port])
    monkeypatch.setattr(net, "source_ip", lambda host: ip)
    path = tmp_path / "baseline.json"
    args = ["baseline", ip, "--out", str(path), "--ports", "9100,631", "--expect", "deny"]
    for port in allowed:
        args += ["--allow", str(port)]
    assert cli.main(args) == 0
    saved = json.loads(path.read_text())
    assert saved["policy"] == {str(p): "allow" if p in allowed else "deny" for p in ports}
    capsys.readouterr()
    assert cli.main(["verify", str(path), "--json"]) == code
    report = json.loads(capsys.readouterr().out)
    assert report["verdict"] == verdict
    assert tuple(row["classification"] for row in report["results"][ip].values()) == classes
    assert report["liveness"][ip] == (["verify-response"] if states[1] != "filtered" else [])


def test_verify_reference_and_attestation(monkeypatch, tmp_path, capsys):
    from datetime import datetime, timedelta, timezone

    ip = "127.0.0.1"
    other = "127.0.0.2"
    state = "open"
    monkeypatch.setattr(verify.net, "tcp_open", lambda *args: state)
    monkeypatch.setattr(verify.net, "source_ip", lambda host: ip)
    path, ref = tmp_path / "baseline.json", tmp_path / "ref.json"
    saved = verify.baseline([ip], [9100], path, "legacy")
    del saved["policy"]
    path.write_text(json.dumps(saved))
    assert cli.main(["snapshot", ip, "--out", str(ref), "--ports", "9100"]) == 0
    snapshot = json.loads(ref.read_text())
    assert snapshot["reference"] is True
    state = "filtered"
    assert verify.compare(path)["verdict"] == "INCONCLUSIVE"
    assert verify.compare(path, reference=ref)["liveness"][ip] == ["reference-snapshot"]
    capsys.readouterr()
    assert cli.main(["verify", str(path), "--printer-online", "--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["liveness"][ip] == ["operator-asserted"]
    assert "weaker" in report["liveness_note"]
    snapshot["results"][other] = snapshot["results"].pop(ip)
    with pytest.raises(ValueError, match="open port for 127.0.0.1"):
        verify.compare(path, reference=snapshot)
    snapshot["results"][ip] = snapshot["results"].pop(other)
    snapshot["created"] = (datetime.now(timezone.utc) - timedelta(minutes=31)).isoformat()
    with pytest.raises(ValueError, match="30 minutes"):
        verify.compare(path, reference=snapshot)


def test_demo_submits_and_records_one_raw_job_without_sockets(monkeypatch, tmp_path, capsys):
    from printer_goblin import net

    ip = "127.0.0.1"
    actions = []

    class Connection:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            actions.append("close")

        def sendall(self, data):
            assert data.startswith(pjl.UEL) and b"%!PS" in data and data.endswith(pjl.UEL)
            assert data.split(b"\x1b%-12345X@PJL EOJ")[0].rstrip().endswith(b"showpage")
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

    monkeypatch.setenv("PRINTER_GOBLIN_STATE", str(tmp_path))
    monkeypatch.setattr(cli, "identify", Fingerprint)
    monkeypatch.setattr(net, "source_ip", lambda host: ip)
    monkeypatch.setattr(safety, "confirm", confirm)
    monkeypatch.setattr(socket, "create_connection", connect)
    args = ["demo", ip, "--format", "ps", "--yes-i-am-authorized"]
    assert cli.main(args) == 0
    assert actions == ["confirm", "connect", "send", "shutdown", "receive", "close"]
    output = capsys.readouterr().out
    assert "Submitted (raw port 9100 gives no confirmation)." in output
    assert output.rstrip().endswith("Physical print not confirmed by software - check the printer.")
    assert "Accepted" not in output and "Completed" not in output
    records = [json.loads(line) for line in (tmp_path / "audit.log").read_text().splitlines()]
    assert records[-1]["event"] == records[-1]["status"] == "submitted"
    assert cli.main(args) == 1
    assert actions.count("connect") == 1
    assert ip in json.loads((tmp_path / "print-history.json").read_text())


def test_slow_printer_ports_are_retried(monkeypatch):
    """A waking printer answers slowly; a short timeout must not mislabel it."""
    from printer_goblin import discovery, net

    def fake(host, port, timeout, accurate=False):
        if host != "192.168.9.5":
            return "filtered"
        if port == 515:
            return "open"
        return "open" if timeout >= net.SLOW_RETRY_TIMEOUT else "filtered"

    monkeypatch.setattr(net, "tcp_open", fake)
    hosts = discovery.discover("192.168.9.0/29", ports=(9100, 515, 80))
    assert [(h.ip, sorted(h.open_ports)) for h in hosts] == [("192.168.9.5", [80, 515, 9100])]
    states = net.probe_with_retry([("192.168.9.5", 80)], 0.8)
    assert states[("192.168.9.5", 80)] == "open"


def test_scan_estimate_warns_only_for_large_ranges():
    from printer_goblin import discovery
    small = discovery.scan_estimate("192.168.1.0/24")
    assert not small["large"] and small["hosts"] == 254 and "intrusion" not in small["message"]
    big = discovery.scan_estimate("10.20.0.0/16")
    assert big["large"] and big["hosts"] == 65534 and "intrusion-detection" in big["message"]
    assert 60 * 60 <= big["seconds"] <= 75 * 60  # worst case at the paced probe rate
    assert "minutes" in big["message"]


@pytest.mark.parametrize("tty,answer,expected", [
    (True, "n", False), (True, "", False), (True, "y", True), (False, None, True)])
def test_large_scan_asks_first_when_interactive(monkeypatch, capsys, tty, answer, expected):
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: tty)
    asked = []

    def ask(prompt):
        asked.append(prompt)
        return answer

    assert cli._scan_go_ahead("10.20.0.0/16", (9100, 631), ask=ask) is expected
    assert bool(asked) == tty
    assert "intrusion-detection" in capsys.readouterr().err


def test_small_scan_never_asks(monkeypatch):
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: True)
    assert cli._scan_go_ahead("192.168.1.0/24", (9100,), ask=lambda prompt: pytest.fail("asked")) is True
