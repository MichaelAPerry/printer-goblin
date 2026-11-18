"""End-to-end tests against the built-in fake printer (loopback only)."""

import json
import socket

import pytest

from printer_goblin import cli, emulator, net, safety, workflow
from printer_goblin.emulator import FakePrinter, escpos_commands, pwg_pages
from printer_goblin.identify import identify
from printer_goblin.payloads.notice import Notice
from printer_goblin.protocols import ipp, snmp

HOST = "127.0.0.1"


@pytest.fixture(autouse=True)
def typed(monkeypatch):
    """What the operator types at the confirmation prompt (real safety.confirm runs)."""
    answer = {"text": "127.0.0.1"}
    # confirm() binds input() as a default argument, so patch the default.
    monkeypatch.setattr(safety.confirm, "__defaults__", (lambda prompt="": answer["text"],))
    return answer


@pytest.fixture(autouse=True)
def _isolated(monkeypatch, tmp_path, localhost_tcp, typed):
    monkeypatch.setenv("PRINTER_GOBLIN_STATE", str(tmp_path / "state"))
    monkeypatch.setattr(workflow, "_JOB_POLL_INTERVAL", 0.05)


@pytest.fixture
def fake(request):
    profile = getattr(request, "param", "office-open")
    with FakePrinter(profile, job_delay=0.15) as printer, net.port_overrides(printer.overrides(), HOST):
        yield printer
    assert not net.PORT_OVERRIDES


def audit(tmp_path):
    lines = (tmp_path / "state" / "audit.log").read_text().splitlines()
    return [json.loads(line) for line in lines]


@pytest.mark.parametrize("fake,ports,kind,languages", [
    ("office-open", [9100, 631, 515, 80], "office", ["pwg-raster", "urf"]),
    ("office-locked", [631], "office", ["pdf", "pwg-raster"]),
    ("receipt", [9100], "thermal", ["escpos"]),
], indirect=["fake"])
def test_identify(fake, ports, kind, languages):
    fp = identify(HOST)
    assert (fp.ports, fp.kind, fp.languages) == (ports, kind, languages)
    assert fp.snmp_ok == (fake.profile.snmp is not None)
    assert fp.ipp_ok == fake.profile.ipp
    assert fp.http_ok == (fake.profile.http_title is not None)
    if fake.profile_name == "office-open":
        assert fp.model == "Goblin Labs FakeJet 100"
        assert fp.firmware == "FJ-1.04"
        assert fp.http_title == "Goblin Labs FakeJet 100"
        assert fp.snmp_values["sysDescr"] == "Goblin Labs FakeJet 100"
    if fake.profile_name == "receipt":
        assert fp.snmp_values["sysDescr"] == "EPSON TM-T88VI"
        assert 631 not in fake.port_map and 80 not in fake.port_map


def test_office_open_prints_pwg_over_ipp(fake, tmp_path):
    assert cli.main(["demo", HOST, "--yes-i-am-authorized"]) == 0
    assert len(fake.jobs) == 1
    job = fake.jobs[0]
    assert job["format"] == "image/pwg-raster" and job["copies"] == 1
    assert pwg_pages(job["document"]) == 1
    last = audit(tmp_path)[-1]
    assert last["event"] == "completed" and last["job_impressions_completed"] == 1
    assert last["job_state"] == 9 and last["job_id"] == job["job_id"]
    assert fake.raw_jobs == []  # IPP was used, not 9100


def test_ipp_operations(fake):
    def call(operation, **kwargs):
        request = ipp.encode_request(operation, f"ipp://{HOST}:631/ipp/print", **kwargs)
        return ipp._decode_response(ipp._post(HOST, 631, "/ipp/print", 2, request)[1])

    assert call(0x0004, document_format="image/pwg-raster", data=b"x")[0] == 0
    assert fake.jobs == []  # Validate-Job never stores a document
    assert call(0x0010)[0] == 0x0501  # Cancel-Job is not implemented
    assert call(0x0009, job_id=99)[0] == 0x0406
    status, _, attrs = call(0x0002, document_format="text/plain", data=b"hello")
    assert status == 0 and fake.jobs[0]["document"] == b"hello"
    assert attrs["job-id"] == [fake.jobs[0]["job_id"]]
    assert [r["operation"] for r in fake.ipp_requests] == [0x0004, 0x0010, 0x0009, 0x0002]


@pytest.mark.parametrize("fake", ["office-locked"], indirect=True)
def test_office_locked_refuses_cleanly(fake, tmp_path, capsys):
    attrs = ipp.get_printer_attributes(HOST)
    assert attrs["uri-authentication-supported"] == ["requesting-user-name", "basic"]
    assert attrs["uri-security-supported"][0] == "none"
    request = ipp.encode_request(0x0004, f"ipp://{HOST}:631/ipp/print")
    assert ipp._decode_response(ipp._post(HOST, 631, "/ipp/print", 2, request)[1])[0] == 0x0403
    assert cli.main(["demo", HOST, "--yes-i-am-authorized"]) == 1
    assert "0x0403" in capsys.readouterr().err
    assert fake.jobs == [] and fake.raw_jobs == []
    assert [r["status"] for r in fake.ipp_requests if r["operation"] in (2, 4)] == [0x0403] * 3
    assert audit(tmp_path)[-1]["event"] == "failed"


@pytest.mark.parametrize("fake", ["receipt"], indirect=True)
@pytest.mark.parametrize("flags", [[], ["--paper", "58"], ["--raster-qr"], ["--paper", "58", "--raster-qr"]])
def test_receipt_demo_is_safe_escpos(fake, flags):
    assert cli.main(["demo", HOST, "--yes-i-am-authorized", *flags]) == 0
    assert fake.wait_for(lambda: len(fake.raw_jobs) == 1)
    commands = escpos_commands(fake.raw_jobs[0])
    assert commands[0] == "init" and commands[-1] == "cut"
    assert not [c for c in commands if c.startswith(("unsafe:", "unknown:"))]
    assert any(c.startswith("raster(") for c in commands)
    assert any(c.startswith("qr(") for c in commands) == ("--raster-qr" not in flags)


@pytest.mark.parametrize("paper", ["58", "80"])
@pytest.mark.parametrize("native_qr", [True, False])
@pytest.mark.parametrize("mascot", [True, False])
def test_rendered_receipts_are_safe(paper, native_qr, mascot):
    notice = Notice("You've been (gobbed)!", ["\x1bp\x00 line \x10\x14 text"], "https://example.org/")
    notice.mascot = mascot
    commands = escpos_commands(workflow.render_notice(notice, "escpos", paper, native_qr))
    assert not [c for c in commands if c.startswith(("unsafe:", "unknown:"))]


def test_decoder_flags_dangerous_sequences():
    for data, name in [(b"\x1bp\x00\x19\xfa", "drawer"), (b"\x10\x14\x01\x00\x01", "DLE DC4"),
                       (b"\x1b(A\x04\x00\x30\x01\x02\x03", "buzzer"), (b"\x1b\x42\x02\x02", "buzzer"),
                       (b"\x1d(E\x03\x00\x01\x49\x4e", "nv-write")]:
        assert any(c.startswith("unsafe:") and name in c for c in escpos_commands(b"\x1b@" + data + b"\x1dV\x42\x03"))
    # Dangerous byte values inside a raster payload are not commands.
    raster = b"\x1dv0\x00\x02\x00\x02\x00\x1bp\x10\x14"
    assert escpos_commands(raster) == ["raster(16x2)"]


def test_snmp_only_answers_public_get(fake):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(0.3)
    request = snmp.encode_get([snmp.OIDS["sysDescr"]], 7, "public")
    for packet in (snmp.encode_get([snmp.OIDS["sysDescr"]], 7, "private"),
                   request.replace(b"\xa0", b"\xa3", 1)):
        sock.sendto(packet, (HOST, fake.port_map[161]))
        with pytest.raises(socket.timeout):
            sock.recv(4096)
    sock.sendto(request, (HOST, fake.port_map[161]))
    assert snmp.decode_response(sock.recv(4096), 7)[snmp.OIDS["sysDescr"]] == "Goblin Labs FakeJet 100"
    sock.close()


def test_lpd_and_http(fake):
    with socket.create_connection((HOST, fake.port_map[515]), 2) as conn:
        assert conn.recv(10) == b""
    assert fake.wait_for(lambda: fake.lpd_connections == 1)
    assert identify(HOST).http_title == "Goblin Labs FakeJet 100"
    assert fake.http_requests == ["/"]


@pytest.mark.parametrize("fake", ["office-locked"], indirect=True)
def test_locked_profile_has_no_other_services(fake):
    assert sorted(fake.port_map) == [631]
    # Windows reports a refusal only after ~2 s of SYN retries; accurate mode waits for it.
    assert net.tcp_open(HOST, 9100, 0.5, accurate=True) == "closed"


def test_verify_reports_exposed(fake, tmp_path):
    baseline = tmp_path / "baseline.json"
    assert cli.main(["baseline", HOST, "--out", str(baseline), "--label", "demo"]) == 0
    saved = json.loads(baseline.read_text())
    assert saved["policy"] == {str(p): "deny" for p in (9100, 631, 515, 80, 443)}
    assert saved["results"][HOST] == {"9100": "open", "631": "open", "515": "open",
                                      "80": "open", "443": "closed"}
    report = workflow.verify(baseline)
    assert report["verdict"] == "EXPOSED"
    assert report["results"][HOST]["9100"]["classification"] == "EXPOSED"
    assert report["results"][HOST]["443"]["classification"] == "BLOCKED"
    assert cli.main(["verify", str(baseline)]) == 3


def test_port_overrides_are_loopback_only():
    with pytest.raises(AssertionError):
        with net.port_overrides({631: 1234}, "10.0.0.5"):
            pass
    net.PORT_OVERRIDES[("10.0.0.5", 631)] = 1234
    try:
        with pytest.raises(AssertionError):
            net.actual_port("10.0.0.5", 631)
    finally:
        net.PORT_OVERRIDES.clear()
    assert net.actual_port("10.0.0.5", 631) == 631
    with pytest.raises(ValueError):
        FakePrinter("office-open", "192.168.1.5")


def test_fake_printer_flag_keeps_governor(tmp_path, capsys, typed):
    assert cli.main(["--fake-printer", "receipt", "identify", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["kind"] == "thermal"
    assert not net.PORT_OVERRIDES
    # Still requires --yes-i-am-authorized and the typed address.
    assert cli.main(["--fake-printer", "receipt", "demo"]) == 1
    typed["text"] = "nope"
    assert cli.main(["--fake-printer", "receipt", "demo", "--yes-i-am-authorized"]) == 1
    typed["text"] = HOST
    assert cli.main(["--fake-printer", "receipt", "demo", "--yes-i-am-authorized"]) == 0
    # The 10-minute per-target cooldown applies to the fake printer too.
    assert cli.main(["--fake-printer", "receipt", "demo", "--yes-i-am-authorized"]) == 1
    assert "cooldown" in capsys.readouterr().err
    events = [e["event"] for e in audit(tmp_path)]
    assert events.count("submitted") == 1 and events.count("refused") == 3


def test_unknown_profile():
    with pytest.raises(ValueError):
        FakePrinter("nope")
    assert set(emulator.PROFILES) == {"office-open", "office-locked", "receipt"}
