"""Loopback-only web interface for the shared Printer Gremlin workflow."""

from __future__ import annotations

import hmac
import http.client
import json
import secrets
import webbrowser
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Lock

import segno

from .. import safety, workflow
from ..assets import ASSET_DIR
from ..discovery import DEFAULT_PORTS

_LOOPBACK = "127.0.0.1"
_STATIC = Path(__file__).with_name("static")
_FILES = {
    "/": (_STATIC / "index.html", "text/html; charset=utf-8"),
    "/app.js": (_STATIC / "app.js", "text/javascript; charset=utf-8"),
    "/style.css": (_STATIC / "style.css", "text/css; charset=utf-8"),
    "/mascot.png": (ASSET_DIR / "gremlin_color_256.png", "image/png"),
}
_ERRORS = (ValueError, OSError, safety.PrintRefused, http.client.HTTPException)


def _string(body, name, default=None):
    value = body.get(name, default)
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a string")
    return value


def _ports(body):
    ports = body.get("ports", list(DEFAULT_PORTS))
    if (not isinstance(ports, list) or not 1 <= len(ports) <= 32
            or any(type(port) is not int or not 1 <= port <= 65535 for port in ports)):
        raise ValueError("Enter between 1 and 32 ports in 1..65535.")
    return ports


class GremlinServer(ThreadingHTTPServer):
    def __init__(self, address=(_LOOPBACK, 0)):
        if address[0] != _LOOPBACK:
            raise ValueError("GUI must bind to 127.0.0.1")
        super().__init__(address, Handler)
        self.origin = f"http://{_LOOPBACK}:{self.server_port}"
        self.token = secrets.token_urlsafe(32)
        self.governor = safety.PrintGovernor()
        self.lock = Lock()
        self.worker = ThreadPoolExecutor(max_workers=1)
        self.jobs = {}
        self.plans = {}

    def server_close(self):
        super().server_close()
        self.worker.shutdown(wait=True)

    def _discover(self, cidr, ports):
        report = workflow.discover(cidr, ports)
        with ThreadPoolExecutor(max_workers=8) as pool:
            for host, device in zip(report["hosts"], pool.map(
                    workflow.identify, (host["ip"] for host in report["hosts"]))):
                host.update(kind=device["kind"], model=device["model"])
        return report

    def _baseline_path(self, name):
        directory = safety.state_dir() / "baselines"
        directory.mkdir(exist_ok=True)
        if len(name) != 24 or any(char not in "0123456789abcdef" for char in name):
            raise ValueError("Invalid baseline ID.")
        return directory / (name + ".json")

    def action(self, route, body):
        if route == "/api/discover":
            cidr, ports = _string(body, "cidr"), _ports(body)
            with self.lock:
                if any(not job.done() for job in self.jobs.values()):
                    raise ValueError("A discovery job is already running.")
                if len(self.jobs) >= 16:
                    del self.jobs[next(iter(self.jobs))]
                job_id = secrets.token_hex(12)
                self.jobs[job_id] = self.worker.submit(self._discover, cidr, ports)
            return {"job_id": job_id}
        if route == "/api/poll":
            with self.lock:
                job = self.jobs.get(_string(body, "job_id"))
            if job is None:
                raise ValueError("Unknown discovery job.")
            return {"status": "done", **job.result()} if job.done() else {"status": "running"}
        if route == "/api/identify":
            return workflow.identify(_string(body, "target"))
        if route == "/api/plan":
            via = _string(body, "via", "auto")
            paper = _string(body, "paper", "80")
            native_qr = body.get("native_qr", True)
            if type(native_qr) is not bool:
                raise ValueError("native_qr must be a boolean")
            plan = workflow.plan_print(
                _string(body, "target"), _string(body, "format", "auto"),
                None if via == "auto" else via,
                port=body.get("port"), paper=paper, native_qr=native_qr,
            )
            qr = segno.make(plan.notice.url, error="m", micro=False).svg_inline(border=4, omitsize=True)
            plan_id = secrets.token_hex(12)
            with self.lock:
                if len(self.plans) >= 16:
                    del self.plans[next(iter(self.plans))]
                self.plans[plan_id] = (plan, paper, native_qr)
            return {"plan_id": plan_id, "ip": plan.ip, "port": plan.port,
                    "format": plan.format, "protocol": plan.protocol, "qr": qr,
                    "headline": plan.notice.headline, "lines": plan.notice.lines,
                    "facts": plan.notice.fact_lines(), "url": plan.notice.url,
                    "footer": plan.notice.footer}
        if route in ("/api/print", "/api/download"):
            with self.lock:
                saved = self.plans.get(_string(body, "plan_id"))
            if saved is None:
                raise ValueError("Unknown print plan. Create a preview first.")
            plan, paper, native_qr = saved
            if route == "/api/print":
                return workflow.execute_print(plan, body.get("typed_address"),
                                              body.get("authorized"), self.governor)
            fmt = _string(body, "format")
            if fmt not in workflow.FORMATS:
                raise ValueError("Unknown download format.")
            data = plan.data if fmt == plan.format else workflow.render_notice(
                plan.notice, fmt, paper, native_qr
            )
            return data, workflow.MIME_TYPES[fmt], f"gremlin-notice.{workflow.EXTENSIONS[fmt]}"
        if route == "/api/baseline":
            targets = body.get("targets")
            if (not isinstance(targets, list) or not 1 <= len(targets) <= 1024
                    or any(not isinstance(target, str) for target in targets)):
                raise ValueError("Select at least one and at most 1024 targets.")
            baseline_id = secrets.token_hex(12)
            path = self._baseline_path(baseline_id)
            report = workflow.baseline(targets, _ports(body), path.with_suffix(".tmp"),
                                       _string(body, "label", ""))
            path.with_suffix(".tmp").replace(path)
            return {"id": baseline_id, **report}
        if route == "/api/baselines":
            directory = self._baseline_path("0" * 24).parent
            baselines = []
            for path in sorted(directory.glob("*.json"), reverse=True):
                try:
                    meta = json.loads(path.read_text(encoding="utf-8"))
                    baselines.append({"id": path.stem, "label": meta["label"],
                                      "created": meta["created"]})
                except (OSError, ValueError, KeyError, TypeError):
                    continue
            return {"baselines": sorted(baselines, key=lambda item: item["created"], reverse=True)}
        if route == "/api/verify":
            return workflow.verify(self._baseline_path(_string(body, "id")))
        raise LookupError("Unknown API action.")


class Handler(BaseHTTPRequestHandler):
    def setup(self):
        self.request.settimeout(10)
        super().setup()

    def _respond(self, status, data, mime, filename=None):
        self.send_response(status)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(len(data)))
        if filename is not None:
            self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def end_headers(self):
        self.send_header("Content-Security-Policy", "default-src 'self'; img-src 'self' data:")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def _json(self, status, value):
        self._respond(status, json.dumps(value).encode("utf-8"), "application/json")

    def _allowed(self):
        port = self.server.server_port
        hosts = self.headers.get_all("Host") or []
        origins = self.headers.get_all("Origin") or []
        if (hosts not in ([f"{_LOOPBACK}:{port}"], [f"localhost:{port}"])
                or (origins and origins != [self.server.origin])):
            self._json(403, {"error": "Host or Origin is forbidden."})
            return False
        if self.path.startswith("/api/"):
            tokens = self.headers.get_all("X-Gremlin-Token") or []
            if len(tokens) != 1 or not hmac.compare_digest(
                    tokens[0].encode("utf-8"), self.server.token.encode("ascii")):
                self._json(403, {"error": "Invalid session token."})
                return False
        return True

    def send_error(self, code, message=None, explain=None):
        if code == 501:
            if self._allowed():
                self._json(405, {"error": "Method not allowed."})
            return
        super().send_error(code, message, explain)

    def do_GET(self):
        if not self._allowed():
            return
        if self.path.startswith("/api/"):
            self._json(405, {"error": "Use POST with a JSON object."})
            return
        path, mime = _FILES.get(self.path, (None, None))
        if path is None or not path.is_file():
            self._json(404, {"error": "File not found."})
            return
        self._respond(200, path.read_bytes(), mime)

    def do_POST(self):
        if not self._allowed():
            return
        if not self.path.startswith("/api/"):
            self._json(405, {"error": "POST is available for API actions only."})
            return
        if self.headers.get_content_type() != "application/json":
            self._json(415, {"error": "Send application/json."})
            return
        try:
            lengths = self.headers.get_all("Content-Length") or []
            if len(lengths) != 1 or self.headers.get("Transfer-Encoding"):
                raise ValueError("A single Content-Length is required.")
            size = int(lengths[0])
            if not 1 <= size <= 65536:
                raise ValueError("Invalid JSON body length.")
            body = json.loads(self.rfile.read(size))
            if not isinstance(body, dict):
                raise ValueError("Send a JSON object.")
            result = self.server.action(self.path, body)
        except LookupError as exc:
            self._json(404, {"error": str(exc)})
        except _ERRORS as exc:
            self._json(400, {"error": str(exc)})
        else:
            if isinstance(result, tuple):
                data, mime, filename = result
                self._respond(200, data, mime, filename)
            else:
                self._json(200, result)


def serve(port=0, *, open_browser=True):
    if not 0 <= port <= 65535:
        raise ValueError("GUI port must be in 0..65535")
    with GremlinServer((_LOOPBACK, port)) as server:
        url = f"{server.origin}/#token={server.token}"
        print(f"Open Printer Gremlin at {url}", flush=True)
        if open_browser:
            webbrowser.open(url)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
