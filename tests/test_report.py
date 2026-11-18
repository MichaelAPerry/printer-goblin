"""Assessment exports against the loopback printer emulator."""

import hashlib
import http.client
import json
import re
from html import escape, unescape
from threading import Thread

import pytest

from printer_goblin import cli, emulator, net, report, safety, workflow
from printer_goblin.gui.server import GoblinServer
from printer_goblin.identify import Fingerprint
from printer_goblin.payloads import notice

HOST = "127.0.0.1"


@pytest.fixture(autouse=True)
def isolated_state(monkeypatch, tmp_path):
    monkeypatch.setenv("PRINTER_GOBLIN_STATE", str(tmp_path / "state"))


@pytest.fixture
def fake(request, localhost_tcp):
    profile = getattr(request, "param", "office-open")
    with emulator.FakePrinter(profile) as printer, net.port_overrides(printer.overrides(), HOST):
        yield printer


def test_office_open_report(fake, tmp_path):
    baseline = tmp_path / "baseline.json"
    workflow.baseline([HOST], (631,), baseline)
    governor = safety.PrintGovernor()
    governor.audit("attempt", target=HOST)
    governor.audit("completed", target="printer.local", ip=HOST, status="completed")
    governor.audit("refused", target="127.0.0.2")
    with (safety.state_dir() / "audit.log").open("a") as log:
        log.write("truncated\n")

    assessment = report.build_report(HOST, baseline_path=baseline)
    assert assessment["verify"] == workflow.verify(baseline)
    assert assessment["verify"]["verdict"] == "EXPOSED"
    assert assessment["overall_risk"] == "high"
    assert "UNAUTH_PRINT" in {finding["id"] for finding in assessment["findings"]}
    assert [entry["event"] for entry in assessment["audit"]] == ["attempt", "completed", "validate-job"]
    assert assessment["evidence"]["validate_job_status"] == 0
    assert not fake.jobs and not fake.raw_jobs

    html = report.render_html(assessment)
    assert '#unauth-print"' in html
    assert "data:image/png;base64," in html
    assert "@media print" in html


def assert_integrity(assessment, html):
    embedded = re.search(r'<pre id="evidence-json">(.*?)</pre>', html, re.S)
    evidence = json.loads(unescape(embedded[1]))
    assert evidence == {key: assessment[key] for key in ("evidence", "findings", "verify", "audit")}
    digest = hashlib.sha256(json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    assert digest == assessment["evidence_sha256"]
    assert digest in html


@pytest.mark.parametrize("fake", ["office-locked"], indirect=True)
def test_office_locked_report(fake):
    assessment = report.build_report(HOST, include_audit=False)
    assert "IPP_AUTH_REQUIRED" in {finding["id"] for finding in assessment["findings"]}
    assert assessment["audit"] is None
    assert not fake.jobs


def test_printer_strings_are_escaped_and_serials_masked(monkeypatch):
    hostile = '<script>alert("goblin")</script>'
    serial = "SECRET-9917"
    monkeypatch.setattr(net, "source_ip", lambda ip: HOST)

    def probe(address):
        return Fingerprint(
            address, ports=[23], banners={23: hostile}, http_title=hostile,
            firmware=f"Version {serial}",
            ipp_attrs={"printer-make-and-model": [f"FakeJet {serial.lower()}"],
                       "printer-serial-number": [serial.encode()], serial: [serial.encode().hex()]},
            snmp_values={"prtGeneralSerialNumber": serial, "sysDescr": f"Test {serial}"},
        )

    safety.PrintGovernor().audit("failed", target=HOST, reason=f"Device {serial} failed")
    assessment = report.build_report(HOST, probe=probe)
    assert assessment["evidence"]["http_title"] == hostile
    assert assessment["model"] == "(redacted)"
    assert serial.lower() not in json.dumps(assessment).lower()
    assert serial.encode().hex() not in json.dumps(assessment)
    monkeypatch.setattr(notice, "guide_link", lambda ref: "javascript:alert(1)", raising=False)
    html = report.render_html(assessment)
    assert_integrity(assessment, html)
    assert hostile not in html
    assert "<script" not in html
    assert escape(hostile, quote=True) in html
    assert 'href="javascript:' not in html
    assert "## Findings" in report.render_markdown(assessment)


@pytest.mark.parametrize("format", ["html", "md", "json"])
def test_cli_report(tmp_path, monkeypatch, capsys, format):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(net, "source_ip", lambda ip: HOST)

    def identify(target, *, validate_job):
        assert validate_job is False
        return Fingerprint(target)

    monkeypatch.setattr(cli, "identify", identify)
    output = tmp_path / "ticket.md"
    options = ["--out", str(output)] if format == "md" else []
    assert cli.main(["report", HOST, "--format", format, "--no-validate-job", *options]) == 0
    path = tmp_path / capsys.readouterr().out.strip()
    if options:
        assert path == output
    else:
        assert re.fullmatch(rf"goblin-report-127\.0\.0\.1-\d{{8}}-\d{{4}}\.{format}", path.name)
    data = path.read_text(encoding="utf-8")
    if format == "json":
        assessment = json.loads(data)
        assert assessment["evidence"]["validate_job_status"] is None
        assert assessment["audit"] == []
    else:
        assert data.startswith("<!doctype html>" if format == "html" else "# Printer Goblin")


def test_cli_report_with_fake_printer(tmp_path, localhost_tcp):
    path = tmp_path / "assessment.json"
    assert cli.main(["--fake-printer", "office-open", "report", "--format", "json",
                     "--out", str(path)]) == 0
    assessment = json.loads(path.read_text(encoding="utf-8"))
    assert assessment["target"] == HOST
    assert assessment["evidence"]["validate_job_status"] == 0


def test_gui_report_download(fake):
    with GoblinServer() as server:
        thread = Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01})
        thread.start()
        connection = http.client.HTTPConnection(HOST, server.server_port, timeout=5)

        def request(**headers):
            connection.request("POST", "/api/report", json.dumps({"target": HOST}),
                               {"Content-Type": "application/json", **headers})
            response = connection.getresponse()
            return response.status, response.headers, response.read()

        try:
            assert request()[0] == 403
            token = {"X-Goblin-Token": server.token}
            assert request(**token, Origin="http://evil.test")[0] == 403
            assert request(**token, Host="evil.test")[0] == 403
            status, headers, body = request(**token)
            assert status == 200
            assert headers["Content-Type"] == "text/html; charset=utf-8"
            assert headers["Content-Disposition"].startswith('attachment; filename="goblin-report-127.0.0.1-')
            assert "script-src 'none'" in headers["Content-Security-Policy"]
            assert b"#unauth-print" in body
        finally:
            connection.close()
            server.shutdown()
            thread.join()
