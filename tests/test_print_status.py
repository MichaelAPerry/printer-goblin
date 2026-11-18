import inspect
import json
import struct
from http.server import BaseHTTPRequestHandler, HTTPServer
from io import BytesIO
from threading import Thread
from types import SimpleNamespace

import pytest

from printer_goblin import safety, transports, workflow
from printer_goblin.identify import Fingerprint
from printer_goblin.protocols import ipp


def attribute(tag, name, value):
    name = name.encode("ascii")
    value = struct.pack(">i", value) if isinstance(value, int) else value.encode("ascii")
    return bytes([tag]) + struct.pack(">H", len(name)) + name + struct.pack(">H", len(value)) + value


def fake_printer(states, requests):
    class Printer(BaseHTTPRequestHandler):
        def do_POST(self):
            body = self.rfile.read(int(self.headers["Content-Length"]))
            op, request_id = struct.unpack_from(">HI", body, 2)
            requests.append((op, self.path, ipp.decode_response(body)))
            if op == 0x0002:
                values = attribute(0x21, "job-id", 7)
                status = 1
            elif op == 0x0009:
                state, reason = next(states)
                values = attribute(0x23, "job-state", state)
                values += attribute(0x44, "job-state-reasons", reason)
                if state == 9:
                    values += attribute(0x21, "job-impressions-completed", 1)
                status = 0
            else:
                self.send_error(400)
                return
            data = struct.pack(">BBHI", 1, 1, status, request_id) + b"\x02" + values + b"\x03"
            self.send_response(200)
            self.send_header("Content-Type", "application/ipp")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *args):
            pass

    return Printer


@pytest.fixture(params=["in-memory", "localhost"])
def serve_printer(request, monkeypatch):
    if request.param == "localhost":
        request.getfixturevalue("localhost_tcp")
        server = None
        worker = None

        def start(handler):
            nonlocal server, worker
            server = HTTPServer(("127.0.0.1", 0), handler)
            worker = Thread(target=server.serve_forever)
            worker.start()
            return server.server_port

        try:
            yield start
        finally:
            if server is not None:
                server.shutdown()
                worker.join()
                server.server_close()
    else:
        connection = ipp.http.client.HTTPConnection

        def start(handler):
            class FakeSocket:
                def __init__(self):
                    self.wire = bytearray()

                def sendall(self, data):
                    self.wire.extend(data)

                def makefile(self, mode):
                    incoming = BytesIO(self.wire)
                    outgoing = BytesIO()
                    server = handler.__new__(handler)
                    server.rfile, server.wfile = incoming, outgoing
                    server.client_address = ("127.0.0.1", 12345)
                    server.handle()
                    return BytesIO(outgoing.getvalue())

                def close(self):
                    pass

            def connect(host, port, timeout):
                assert host == "127.0.0.1"
                client = connection(host, port, timeout)
                client.sock = FakeSocket()
                return client

            monkeypatch.setattr(ipp.http.client, "HTTPConnection", connect)
            return 8631

        yield start


@pytest.mark.parametrize("states,expected", [
    ([(3, "job-queued"), (9, "job-completed-successfully")], "completed"),
    ([(8, "aborted-by-system")], "failed"),
    ([(7, "job-canceled-by-user")], "failed"),
    ([(5, "job-printing")] * 30, "pending"),
])
def test_ipp_job_status(serve_printer, monkeypatch, tmp_path, states, expected):
    requests = []
    port = serve_printer(fake_printer(iter(states), requests))
    clock = [1000.0]
    delays = []

    def sleep(delay):
        delays.append(delay)
        clock[0] += delay

    monkeypatch.setattr(workflow, "time", SimpleNamespace(monotonic=lambda: clock[0], sleep=sleep))
    monkeypatch.setattr(workflow, "fingerprint_target", Fingerprint)
    monkeypatch.setattr(workflow.net, "source_ip", lambda ip: ip)
    plan = workflow.plan_print("127.0.0.1", "pdf", "ipp", port=port)
    governor = safety.PrintGovernor(directory=tmp_path)
    reports = []

    def progress(report):
        reports.append(report)
        if report["status"] == "accepted":
            with pytest.raises(safety.PrintRefused, match="cooldown"):
                governor.check(plan.ip, len(plan.data))

    result = workflow.execute_print(plan, plan.ip, True, governor, on_status=progress)
    assert [report["status"] for report in reports] == ["submitted", "accepted", expected]
    assert (result["ipp_status"], result["job_id"], result["job_state"]) == (1, 7, states[-1][0])
    assert result["job_state_reasons"] == [states[-1][1]]
    assert result["note"] == workflow.PHYSICAL_PRINT_NOTE
    assert states[-1][1] in workflow.print_status_text(result)
    if expected == "completed":
        assert result["job_impressions_completed"] == 1
    if expected == "pending":
        assert delays == [3] * 30
    assert [op for op, _, _ in requests] == [0x0002, *[0x0009] * len(states)]
    for _, path, attrs in requests[1:]:
        assert path == "/ipp/print"
        assert attrs["printer-uri"] == [f"ipp://127.0.0.1:{port}{path}"]
        assert attrs["job-id"] == [7]
        assert attrs["requested-attributes"] == [
            "job-state", "job-state-reasons", "job-impressions-completed",
        ]
    audit = [json.loads(line) for line in (tmp_path / "audit.log").read_text().splitlines()]
    assert audit[-1]["event"] == audit[-1]["status"] == expected


def test_ipp_tls_api_removed():
    for call in (ipp.get_printer_attributes, ipp.query_printer, ipp.print_job,
                 ipp.get_job_attributes, transports.send_ipp):
        assert "tls" not in inspect.signature(call).parameters
    assert not hasattr(Fingerprint("127.0.0.1"), "ipp_tls")
