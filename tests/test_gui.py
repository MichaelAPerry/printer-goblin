import http.client
import json
import socket
import time
from concurrent.futures import ThreadPoolExecutor
from io import BytesIO
from threading import Thread

import pytest

from printer_gremlin import safety, workflow
from printer_gremlin.gui.server import GremlinServer, Handler
from printer_gremlin.identify import Fingerprint


@pytest.fixture
def local_plan(monkeypatch):
    monkeypatch.setattr(workflow, "fingerprint_target", Fingerprint)
    monkeypatch.setattr(workflow.net, "source_ip", lambda ip: ip)
    return lambda port=9100: workflow.plan_print("127.0.0.1", "ps", port=port)


def test_execute_refusals(tmp_path, local_plan, monkeypatch):
    governor = safety.PrintGovernor(directory=tmp_path)
    plan = local_plan()

    def unexpected(*args):
        pytest.fail("refused plan reached the transport")

    monkeypatch.setattr(workflow.transports, "send_raw", unexpected)
    with pytest.raises(safety.PrintRefused, match="confirmation declined"):
        workflow.execute_print(plan, "127.0.0.2", True, governor)
    for unauthorized in (False, 1):
        with pytest.raises(safety.PrintRefused, match="explicit authorization"):
            workflow.execute_print(plan, plan.ip, unauthorized, governor)
    governor.record(plan.ip)
    with pytest.raises(safety.PrintRefused, match="cooldown"):
        workflow.execute_print(plan, plan.ip, True, governor)
    audit = [json.loads(line) for line in (tmp_path / "audit.log").read_text().splitlines()]
    assert [entry["event"] for entry in audit] == ["attempt", "refused"] * 4


def test_execute_one_job(localhost_tcp, tmp_path, local_plan):
    governor = safety.PrintGovernor(directory=tmp_path)
    with socket.socket() as printer, ThreadPoolExecutor(max_workers=1) as pool:
        printer.bind(("127.0.0.1", 0))
        printer.listen()
        printer.settimeout(3)
        plan = local_plan(printer.getsockname()[1])

        def receive():
            connection, _ = printer.accept()
            with connection, connection.makefile("rb") as stream:
                connection.settimeout(3)
                return stream.read()

        job = pool.submit(receive)
        assert workflow.execute_print(plan, plan.ip, True, governor)["status"] == "sent"
        assert job.result() == plan.data
        with pytest.raises(safety.PrintRefused, match="cooldown"):
            workflow.execute_print(plan, plan.ip, True, governor)
        printer.setblocking(False)
        with pytest.raises(BlockingIOError):
            printer.accept()


def test_gui_api(localhost_tcp, tmp_path, monkeypatch, local_plan):
    monkeypatch.setenv("PRINTER_GREMLIN_STATE", str(tmp_path))
    with GremlinServer() as server:
        worker = Thread(target=server.serve_forever)
        worker.start()
        try:
            def request(route, body=None, **headers):
                with_connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=5)
                try:
                    if body is None:
                        with_connection.request("GET", route, headers=headers)
                    else:
                        headers.update({"Content-Type": "application/json"})
                        with_connection.request("POST", route, json.dumps(body), headers)
                    response = with_connection.getresponse()
                    assert response.getheader("Cache-Control") == "no-store"
                    return response.status, response.read()
                finally:
                    with_connection.close()

            token = {"X-Gremlin-Token": server.token}
            assert request("/")[0] == 200
            assert request("/api/baselines", {})[0] == 403
            assert request("/", Host="evil.example")[0] == 403
            assert request("/api/baselines", {}, Origin="https://evil.example", **token)[0] == 403
            status, encoded = request("/api/discover", {
                "cidr": "127.0.0.1/32", "ports": [server.server_port],
            }, **token)
            assert status == 200
            for _ in range(100):
                status, data = request("/api/poll", json.loads(encoded), **token)
                assert status == 200
                result = json.loads(data)
                if result["status"] == "done":
                    break
                time.sleep(.05)
            assert result["hosts"][0]["ip"] == "127.0.0.1"
            status, encoded = request("/api/plan", {"target": "127.0.0.1", "format": "ps"}, **token)
            assert status == 200
            plan_id = json.loads(encoded)["plan_id"]
            status, data = request("/api/print", {
                "plan_id": plan_id, "typed_address": "127.0.0.2", "authorized": True,
            }, **token)
            assert status == 400 and json.loads(data)["error"] == "Address confirmation declined."
        finally:
            server.shutdown()
            worker.join()


def test_gui_non_loopback_refused():
    with pytest.raises(ValueError, match="127.0.0.1"):
        GremlinServer(("0.0.0.0", 0))


def test_gui_http_dispatch_without_sockets(tmp_path, monkeypatch, local_plan):
    from threading import Lock

    monkeypatch.setenv("PRINTER_GREMLIN_STATE", str(tmp_path))
    monkeypatch.setattr(workflow.net, "tcp_open", lambda ip, port, timeout: "open")
    monkeypatch.setattr(Handler, "log_message", lambda *args: None)
    server = GremlinServer.__new__(GremlinServer)
    server.server_port = 8000
    server.origin = "http://127.0.0.1:8000"
    server.token = "test-only-token"
    server.governor = safety.PrintGovernor(directory=tmp_path)
    server.lock, server.jobs, server.plans = Lock(), {}, {}

    def request(path, body=None, host="127.0.0.1:8000", token=server.token, origin=None):
        payload = b"" if body is None else json.dumps(body).encode()
        method = "GET" if body is None else "POST"
        headers = [f"{method} {path} HTTP/1.1", f"Host: {host}",
                   "Content-Type: application/json", f"Content-Length: {len(payload)}"]
        if token is not None:
            headers.append(f"X-Gremlin-Token: {token}")
        if origin is not None:
            headers.append(f"Origin: {origin}")
        wire = "\r\n".join(headers).encode() + b"\r\n\r\n" + payload
        outgoing = BytesIO()
        handler = Handler.__new__(Handler)
        handler.server = server
        handler.client_address = ("127.0.0.1", 12345)
        handler.rfile, handler.wfile = BytesIO(wire), outgoing
        handler.handle()
        response_header, data = outgoing.getvalue().split(b"\r\n\r\n", 1)
        assert b"Content-Security-Policy: default-src 'self'; img-src 'self' data:" in response_header
        assert b"X-Content-Type-Options: nosniff" in response_header
        assert b"Cache-Control: no-store" in response_header
        return int(response_header.split()[1]), data

    with ThreadPoolExecutor(max_workers=1) as server.worker:
        assert request("/")[0] == 200
        assert request("/", host="localhost:8000")[0] == 200
        assert request("/api/baselines", {}, token=None)[0] == 403
        assert request("/api/baselines", {}, token="wrong")[0] == 403
        assert request("/", host="bad.example")[0] == 403
        assert request("/api/baselines", {}, origin="https://bad.example")[0] == 403
        assert request("/api/baselines")[0] == 405
        status, data = request("/api/discover", {"cidr": "127.0.0.1/32", "ports": [9100]})
        assert status == 200
        job = json.loads(data)
        server.jobs[job["job_id"]].result(timeout=3)
        status, data = request("/api/poll", job)
        assert status == 200 and json.loads(data)["hosts"][0]["open_ports"] == [9100]
        status, data = request("/api/plan", {"target": "127.0.0.1", "format": "ps"})
        assert status == 200
        plan = json.loads(data)
        assert "<svg" in plan["qr"] and "viewBox=" in plan["qr"]
        assert request("/api/download", {"plan_id": plan["plan_id"], "format": "pdf"})[1].startswith(b"%PDF-1.4")
        status, data = request("/api/print", {
            "plan_id": plan["plan_id"], "typed_address": "127.0.0.2", "authorized": True,
        })
        assert status == 400 and json.loads(data)["error"] == "Address confirmation declined."
        status, data = request("/api/baseline", {"targets": ["127.0.0.1"], "ports": [9100]})
        assert status == 200
        status, data = request("/api/verify", {"id": json.loads(data)["id"]})
        assert status == 200 and json.loads(data)["verdict"] == "FAIL"


def test_execute_serializes_concurrent_requests(tmp_path, local_plan, monkeypatch):
    from threading import Barrier

    governor = safety.PrintGovernor(directory=tmp_path)
    plan = local_plan()
    jobs = []
    monkeypatch.setattr(workflow.transports, "send_raw",
                        lambda ip, data, port: jobs.append((ip, port, data)))
    start = Barrier(2, timeout=3)

    def execute():
        start.wait()
        try:
            return workflow.execute_print(plan, plan.ip, True, governor)["status"]
        except safety.PrintRefused as exc:
            assert "cooldown" in str(exc)
            return "refused"

    with ThreadPoolExecutor(max_workers=2) as pool:
        first, second = pool.submit(execute), pool.submit(execute)
        assert sorted([first.result(), second.result()]) == ["refused", "sent"]
    assert jobs == [(plan.ip, plan.port, plan.data)]
