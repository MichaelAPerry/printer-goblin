"""Fleet assessment: consolidated report from injected fakes and the loopback emulator."""

import ast
import csv
import hashlib
import http.client
import io
import json
import re
import time
from html import escape, unescape
from pathlib import Path
from threading import Thread

import pytest

from printer_goblin import cli, emulator, fleet, net, safety, scope, transports
from printer_goblin.gui.server import GoblinServer
from printer_goblin.identify import Fingerprint
from printer_goblin.payloads import notice
from printer_goblin.protocols import ipp

HOST = "127.0.0.1"
SERIAL = "SN-SECRET-4411"
OPEN, LOCKED, UNKNOWN, BROKEN = "10.0.0.4", "10.0.0.9", "10.0.0.12", "10.0.0.13"


@pytest.fixture(autouse=True)
def isolated(monkeypatch, tmp_path):
    monkeypatch.setenv("PRINTER_GOBLIN_STATE", str(tmp_path / "state"))
    monkeypatch.setattr(net, "source_ip", lambda ip: HOST)
    monkeypatch.setattr(net, "source_label", lambda ip: "test-host (127.0.0.1)")


def fake_devices(model_open=f"FakeJet {SERIAL}"):
    return {
        OPEN: Fingerprint(
            OPEN, ports=[9100, 23, 631, 80], kind="office", ipp_ok=True, http_ok=True, validate_job_status=0,
            ipp_attrs={"printer-make-and-model": [model_open],
                       "printer-serial-number": [SERIAL], "printer-info": [f"unit {SERIAL}"]},
            languages=["pdf"]),
        LOCKED: Fingerprint(
            LOCKED, ports=[631, 443], kind="office", ipp_ok=True, validate_job_status=0x0401,
            ipp_attrs={"printer-make-and-model": ["LockedJet 200"]}),
        UNKNOWN: Fingerprint(UNKNOWN, ports=[9100]),
        BROKEN: Fingerprint(BROKEN, ports=[80]),
    }


def injected(devices=None, *, hosts=(OPEN, LOCKED, UNKNOWN), broken=()):
    devices = devices or fake_devices()

    def discover(cidr, ports):
        return [{"ip": ip, "open_ports": devices[ip].ports} for ip in hosts]

    def identify(ip):
        if ip in broken:
            raise TimeoutError("timed out talking to printer")
        return devices[ip]

    return {"discover": discover, "identify": identify}


@pytest.fixture
def result():
    return fleet.assess_fleet("10.0.0.0/24", **injected())


def by_ip(result, ip):
    return next(d for d in result["devices"] if d["ip"] == ip)


def test_structure_prevalence_and_severity(result):
    assert result["host_count"] == 3 and result["assessed_count"] == 3 and result["error_count"] == 0
    assert result["range"] == "10.0.0.0/24" and result["source"] == "test-host (127.0.0.1)"
    assert result["tool"]["name"] == "Printer Goblin"
    assert result["overall_risk"] == "high"
    prevalence = {row["id"]: row for row in result["prevalence"]}
    assert prevalence["RAW9100"]["ips"] == [OPEN, UNKNOWN]
    assert prevalence["RAW9100"]["label"] == "2 of 3 printers"
    assert prevalence["TELNET"]["count"] == 1 and prevalence["TELNET"]["of"] == 3
    assert prevalence["UNAUTH_PRINT"]["ips"] == [OPEN]
    assert prevalence["IPP_PLAIN"]["ips"] == [OPEN, LOCKED]
    assert prevalence["IPP_AUTH_REQUIRED"]["severity"] == "info"
    totals = result["severity_totals"]
    assert totals["high"] == 4 and sum(totals.values()) == sum(len(d["findings"]) for d in result["devices"])
    assert by_ip(result, OPEN)["overall_risk"] == "high"
    assert by_ip(result, LOCKED)["overall_risk"] == "medium"
    assert result["bottom_line"].startswith("1 of 3 printers validated a print request without a login")


def test_recommendations_ranked_and_worded(result):
    recs = result["recommendations"]
    high = [rec["id"] for rec in recs if rec["severity"] == "high"]
    assert high == ["RAW9100", "TELNET", "UNAUTH_PRINT"]  # severity, then prevalence, then id
    severities = [fleet.base._SEVERITIES.index(rec["severity"]) for rec in recs]
    assert severities == sorted(severities, reverse=True)
    by_id = {rec["id"]: rec for rec in recs}
    assert by_id["RAW9100"]["sentence"] == (
        f"Restrict raw port 9100 to the print server on 2 of 3 printers ({OPEN}, {UNKNOWN})")
    assert by_id["TELNET"]["sentence"] == f"Turn off Telnet on 1 of 3 printers ({OPEN})"
    assert by_id["RAW9100"]["link"] == notice.guide_link("raw-9100")
    unauth = by_id["UNAUTH_PRINT"]
    assert "without a login" in unauth["why"] and "would likely print" in unauth["why"]
    assert unauth["link"].endswith("#unauth-print")
    assert "IPP_AUTH_REQUIRED" not in by_id  # a good result needs no fix
    assert by_id["UNCONFIRMED"]["ips"] == [UNKNOWN]
    assert all(rec["id"] in fleet.RECOMMENDATIONS or rec["id"] == "UNCONFIRMED" for rec in recs)


def test_unconfirmed_printer_is_kept_and_flagged(result):
    unknown = by_ip(result, UNKNOWN)
    assert unknown["kind"] == "unknown" and unknown["unconfirmed"] is True
    assert result["unconfirmed_count"] == 1
    assert not by_ip(result, OPEN)["unconfirmed"]
    html = fleet.render_html(result)
    assert fleet.UNCONFIRMED in html and fleet.UNCONFIRMED in fleet.render_markdown(result)


def test_per_host_errors_are_recorded_not_fatal():
    result = fleet.assess_fleet("10.0.0.0/24", **injected(hosts=(OPEN, BROKEN, UNKNOWN), broken=(BROKEN,)))
    assert result["host_count"] == 3 and result["assessed_count"] == 2 and result["error_count"] == 1
    broken = by_ip(result, BROKEN)
    assert broken["error"] == "TimeoutError: timed out talking to printer"
    assert broken["findings"] == [] and broken["overall_risk"] == "unknown"
    assert by_ip(result, OPEN)["error"] is None
    assert {row["id"]: row["of"] for row in result["prevalence"]}["RAW9100"] == 2  # failed hosts excluded
    assert "1 host could not be assessed" in result["bottom_line"]
    rows = list(csv.reader(io.StringIO(fleet.render_csv(result))))
    assert rows[-1][0] == BROKEN and rows[-1][3] == "error"  # failures sort last
    assert "Assessment failed" in fleet.render_html(result)


def test_progress_callback_reports_every_host():
    seen = []
    fleet.assess_fleet("10.0.0.0/24", on_progress=lambda *args: seen.append(args), **injected())
    assert [(done, total) for done, total, _ in seen] == [(1, 3), (2, 3), (3, 3)]
    assert {entry["ip"] for _, _, entry in seen} == {OPEN, LOCKED, UNKNOWN}


def test_concurrency_is_bounded():
    import threading
    devices = {f"10.0.0.{n}": Fingerprint(f"10.0.0.{n}", ports=[9100], kind="office") for n in range(1, 13)}
    active = {"now": 0, "max": 0}
    lock = threading.Lock()

    def identify(ip):
        with lock:
            active["now"] += 1
            active["max"] = max(active["max"], active["now"])
        time.sleep(0.02)
        with lock:
            active["now"] -= 1
        return devices[ip]

    fleet.assess_fleet("10.0.0.0/24", workers=50, identify=identify,
                       discover=lambda c, p: [{"ip": ip, "open_ports": [9100]} for ip in devices])
    assert 1 < active["max"] <= 4


def test_scope_rules_still_apply():
    for cidr in ("8.8.8.0/24", "10.0.0.0/20", "not-a-range"):
        with pytest.raises(scope.ScopeError):
            fleet.assess_fleet(cidr, **injected())
    hostile = {"discover": lambda c, p: [{"ip": "8.8.8.8", "open_ports": [9100]}],
               "identify": lambda ip: pytest.fail("out-of-scope host was probed")}
    result = fleet.assess_fleet("10.0.0.0/24", **hostile)
    assert result["devices"][0]["error"].startswith("ScopeError")


def test_serials_are_masked_everywhere(result):
    assert by_ip(result, OPEN)["model"] == "(redacted)"
    outputs = [json.dumps(result), fleet.render_html(result), fleet.render_markdown(result),
               fleet.render_csv(result), fleet.to_json(result)]
    for text in outputs:
        assert SERIAL.lower() not in text.lower()


def hostile_result(monkeypatch=None):
    hostile = '<script>alert("goblin")</script>'
    devices = fake_devices(model_open="=HYPERLINK(\"http://x\")")
    devices[OPEN].http_title = hostile
    devices[OPEN].banners = {23: hostile}
    devices[OPEN].firmware = hostile
    devices[UNKNOWN].snmp_values = {"hrDeviceDescr": hostile}
    return hostile, fleet.assess_fleet("10.0.0.0/24", **injected(devices))


def test_html_escapes_printer_strings_and_links(monkeypatch):
    hostile, result = hostile_result()
    monkeypatch.setattr(notice, "guide_link", lambda ref: "javascript:alert(1)")
    html = fleet.render_html(result)
    assert hostile not in html and "<script" not in html
    assert escape(hostile, quote=True) in html
    assert 'href="javascript:' not in html
    assert "script-src 'none'" in unescape(html) and "Content-Security-Policy" in html
    assert "<details>" in html and "<summary>" in html
    for heading in ("Top recommendations", "Devices", "Finding prevalence", "Per-device details",
                    "Methodology and safety", "Appendix"):
        assert heading in html
    assert "nothing is sent to port 9100" in html
    assert "Validate-Job prints nothing" in html
    assert "<script" not in fleet.render_markdown(result)


def test_csv_formula_injection_guard():
    devices = fake_devices(model_open="=HYPERLINK(\"http://x\")")
    devices[LOCKED].ipp_attrs["printer-make-and-model"] = ["-2+3"]
    devices[UNKNOWN].snmp_values = {"hrDeviceDescr": "@SUM(A1)"}
    result = fleet.assess_fleet("10.0.0.0/24", **injected(devices))
    rows = list(csv.reader(io.StringIO(fleet.render_csv(result))))
    assert rows[0] == ["ip", "model", "kind", "risk", "high", "medium", "low", "info", "top_finding"]
    models = {row[0]: row[1] for row in rows[1:]}
    assert models[OPEN] == "'=HYPERLINK(\"http://x\")"
    assert models[LOCKED] == "'-2+3"
    assert models[UNKNOWN] == "'@SUM(A1)"
    assert len(rows) == 4
    assert fleet._csv_cell("+1") == "'+1" and fleet._csv_cell("plain") == "plain"
    risk_rows = {row[0]: row for row in rows[1:]}
    assert risk_rows[OPEN][3] == "high" and risk_rows[OPEN][4] == "3"  # RAW9100, TELNET, UNAUTH_PRINT


def test_sha256_recomputes(result):
    sections = {key: result[key] for key in fleet._SECTIONS}
    canonical = json.dumps(sections, sort_keys=True, separators=(",", ":"))
    assert hashlib.sha256(canonical.encode()).hexdigest() == result["evidence_sha256"]
    html = fleet.render_html(result)
    embedded = json.loads(unescape(re.search(r'<pre id="evidence-json">(.*?)</pre>', html, re.S)[1]))
    assert embedded == json.loads(json.dumps(sections))
    assert hashlib.sha256(json.dumps(embedded, sort_keys=True, separators=(",", ":")).encode()
                          ).hexdigest() == result["evidence_sha256"]
    assert result["evidence_sha256"] in fleet.render_markdown(result)


def test_fleet_module_has_no_print_path():
    tree = ast.parse(Path(fleet.__file__).read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            imported.update(alias.name for alias in node.names)
            imported.add(node.module or "")
        elif isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
    names = {node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)}
    assert not {"transports", "payloads.pdf", "execute_print"} & (imported | names)
    source = Path(fleet.__file__).read_text(encoding="utf-8")
    for forbidden in ("send_raw", "send_ipp", "print_job", "execute_print", "run_demo"):
        assert forbidden not in source


@pytest.fixture
def fake(localhost_tcp):
    with emulator.FakePrinter("office-open") as printer, net.port_overrides(printer.overrides(), HOST):
        yield printer


def test_end_to_end_never_prints(fake, monkeypatch):
    def refuse(*args, **kwargs):
        pytest.fail("fleet assessment reached a print path")

    monkeypatch.setattr(transports, "send_raw", refuse)
    monkeypatch.setattr(transports, "send_ipp", refuse)
    monkeypatch.setattr(ipp, "print_job", refuse)
    result = fleet.assess_fleet(f"{HOST}/32")
    assert result["host_count"] == 1
    device = result["devices"][0]
    assert device["error"] is None and "UNAUTH_PRINT" in {f["id"] for f in device["findings"]}
    assert device["evidence"]["validate_job_status"] == 0
    assert not fake.jobs and not fake.raw_jobs
    assert all(not fake.raw_connections or not data for data in fake.raw_connections)  # connect-only on 9100
    audit = (safety.state_dir() / "audit.log").read_text()
    assert "validate-job" in audit


def test_no_validate_job_skips_the_check(fake):
    result = fleet.assess_fleet(f"{HOST}/32", validate_job=False)
    device = result["devices"][0]
    assert device["evidence"]["validate_job_status"] is None
    assert "UNAUTH_PRINT" not in {f["id"] for f in device["findings"]}
    assert not fake.jobs


@pytest.mark.parametrize("format", ["html", "md", "json", "csv"])
def test_cli_assess_writes_each_format(tmp_path, monkeypatch, capsys, format):
    monkeypatch.chdir(tmp_path)
    real = fleet.assess_fleet
    monkeypatch.setattr(cli.fleet, "assess_fleet",
                        lambda cidr, **kwargs: real(cidr, **kwargs, **injected(broken=(UNKNOWN,))))
    assert cli.main(["assess", "10.0.0.0/24", "--format", format, "--ports", "9100,631"]) == 0
    captured = capsys.readouterr()
    path = tmp_path / captured.out.strip()
    assert re.fullmatch(rf"goblin-fleet-10\.0\.0\.0-24-\d{{8}}-\d{{4}}\.{format}", path.name)
    progress = [line for line in captured.err.splitlines() if re.match(r"\[goblin\] \d/3 10\.0\.0\.", line)]
    assert len(progress) == 3 and any("error" in line for line in progress)
    data = path.read_text(encoding="utf-8")
    if format == "json":
        assert json.loads(data)["host_count"] == 3
    else:
        assert data.startswith({"html": "<!doctype html>", "md": "# Printer Goblin fleet",
                                "csv": "ip,model,kind,risk"}[format])


def test_cli_assess_out_and_requirements(tmp_path, capsys):
    assert cli.main(["assess"]) == 2
    assert cli.main(["assess", "8.8.8.0/24", "--out", str(tmp_path / "x.md")]) == 1
    assert not (tmp_path / "x.md").exists()


def test_cli_assess_with_fake_printer(tmp_path, localhost_tcp):
    path = tmp_path / "fleet.json"
    assert cli.main(["--fake-printer", "office-open", "assess", "--format", "json", "--out", str(path)]) == 0
    result = json.loads(path.read_text(encoding="utf-8"))
    assert result["range"] == "127.0.0.1/32" and result["host_count"] == 1
    assert result["devices"][0]["model"] == "Goblin Labs FakeJet 100"
    assert result["devices"][0]["unconfirmed"] is False
    assert result["recommendations"][0]["id"] == "RAW9100"


def test_gui_fleet_assessment_and_download(fake):
    with GoblinServer() as server:
        thread = Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01})
        thread.start()
        connection = http.client.HTTPConnection(HOST, server.server_port, timeout=10)

        def request(route, body, **headers):
            connection.request("POST", route, json.dumps(body),
                               {"Content-Type": "application/json", **headers})
            response = connection.getresponse()
            return response.status, response.headers, response.read()

        try:
            token = {"X-Goblin-Token": server.token}
            body = {"cidr": f"{HOST}/32", "ports": [9100, 631, 80]}
            assert request("/api/assess", body)[0] == 403
            assert request("/api/assess", body, **token, Origin="http://evil.test")[0] == 403
            assert request("/api/assess", body, **token, Host="evil.test")[0] == 403
            status, _, data = request("/api/assess", body, **token)
            assert status == 200
            job = json.loads(data)
            deadline = time.time() + 10
            while True:
                status, _, data = request("/api/assess-poll", job, **token)
                poll = json.loads(data)
                if poll["status"] == "done" or time.time() > deadline:
                    break
                time.sleep(0.05)
            assert poll["status"] == "done" and poll["host_count"] == 1
            assert request("/api/assess-report", job)[0] == 403
            status, headers, html = request("/api/assess-report", job, **token)
            assert status == 200
            assert headers["Content-Type"] == "text/html; charset=utf-8"
            assert headers["Content-Disposition"].startswith('attachment; filename="goblin-fleet-127.0.0.1-32-')
            assert "script-src 'none'" in headers["Content-Security-Policy"]
            assert b"#unauth-print" in html
            assert request("/api/assess-report", {"job_id": "nope"}, **token)[0] == 400
        finally:
            connection.close()
            server.shutdown()
            thread.join()


def test_web_only_non_printer_is_listed_separately():
    from printer_goblin.identify import Fingerprint

    def discover(cidr, ports):
        return [{"ip": "10.0.0.1", "open_ports": [80, 443]}, {"ip": "10.0.0.5", "open_ports": [9100]}]

    def identify(ip):
        return Fingerprint(ip, ports=[80, 443] if ip.endswith(".1") else [9100], http_ok=ip.endswith(".1"))

    result = fleet.assess_fleet("10.0.0.0/29", discover=discover, identify=identify, validate_job=False)
    assert [h["ip"] for h in result["other_hosts"]] == ["10.0.0.1"]
    assert [d["ip"] for d in result["devices"]] == ["10.0.0.5"]
    assert all("10.0.0.1" not in row["ips"] for row in result["prevalence"])
    assert "Other hosts (not printers)" in fleet.render_html(result)
