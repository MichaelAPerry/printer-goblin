import struct
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread

from printer_gremlin.protocols import ipp, snmp


def test_ipp_request_round_trip():
    encoded = ipp.encode_request(
        2, "ipp://127.0.0.1:631/ipp/print", requested_attributes=("one", "two"),
        document_format="application/pdf", job_name="Notice", data=b"document",
    )
    assert encoded[:8] == struct.pack(">BBHI", 1, 1, 2, 1)
    assert encoded.endswith(b"\x03document")
    assert ipp.decode_response(encoded) == {
        "attributes-charset": ["utf-8"], "attributes-natural-language": ["en"],
        "printer-uri": ["ipp://127.0.0.1:631/ipp/print"],
        "requesting-user-name": ["printer-gremlin"], "requested-attributes": ["one", "two"],
        "document-format": ["application/pdf"], "job-name": ["Notice"], "copies": [1],
    }


def test_crafted_ipp_response():
    response = bytes.fromhex("010100000000000104")
    response += b"\x23\x00\x0dprinter-state\x00\x04\x00\x00\x00\x03"
    response += b"\x22\x00\x04flag\x00\x01\x01"
    response += b"\x49\x00\x06format\x00\x0fapplication/pdf"
    response += b"\x49\x00\x00\x00\x09image/urf"
    response += b"\x33\x00\x05range\x00\x08" + struct.pack(">ii", -2, 10)
    response += b"\x32\x00\x03dpi\x00\x09" + struct.pack(">iiB", 300, 600, 3)
    response += b"\x55\x00\x03raw\x00\x02\x00\xff\x03"
    assert ipp.decode_response(response) == {
        "printer-state": [3], "flag": [True], "format": ["application/pdf", "image/urf"],
        "range": [(-2, 10)], "dpi": [(300, 600, 3)], "raw": [b"\x00\xff"],
    }


def test_crafted_snmp_packet():
    oid = snmp.OIDS["sysDescr"]
    get = bytes.fromhex("302602010004067075626c6963a019020101020100020100300e300c06082b060102010101000500")
    response = bytes.fromhex(
        "302d02010004067075626c6963a2200201010201000201003015301306082b06010201010100"
        "04075072696e746572"
    )
    assert snmp.encode_get([oid], 1) == get
    assert snmp.decode_response(response, 1) == {oid: "Printer"}


def test_ipp_fallback_and_single_submission(localhost_tcp):
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            body = self.rfile.read(int(self.headers["Content-Length"]))
            requests.append((self.path, self.headers["Content-Type"], body))
            if self.path != "/printers/":
                self.send_error(404 if self.path == "/ipp/print" else 400)
                return
            response = bytes.fromhex("0101000000000001")
            if body[2:4] == b"\x00\x02":
                response += b"\x02\x21\x00\x06job-id\x00\x04\x00\x00\x00\x07"
            else:
                response += b"\x04\x49\x00\x19document-format-supported\x00\x0fapplication/pdf"
            self.send_response(200)
            self.send_header("Content-Type", "application/ipp")
            self.end_headers()
            self.wfile.write(response + b"\x03")

    with HTTPServer(("127.0.0.1", 0), Handler) as server:
        runner = Thread(target=server.serve_forever)
        runner.start()
        try:
            port = server.server_port
            attrs, path = ipp.query_printer("127.0.0.1", port)
            assert attrs == {"document-format-supported": ["application/pdf"]}
            assert ipp.print_job("127.0.0.1", b"pdf", "application/pdf", port, path) == (0, 7)
        finally:
            server.shutdown()
            runner.join()
    assert [path for path, _, _ in requests] == ["/ipp/print", "/", "/printers/", "/printers/"]
    assert all(mime == "application/ipp" for _, mime, _ in requests)
    assert requests[-1][2].endswith(b"\x03pdf")


def test_ipp_query_uses_fallback_but_print_job_is_one_shot(monkeypatch):
    paths = []

    def post(host, port, path, timeout, request, on_submit=None):
        paths.append(path)
        if path == "/ipp/print":
            return 404, b""
        if path == "/":
            return 400, b""
        assert ipp.decode_response(request)["printer-uri"] == [f"ipp://{host}:{port}{path}"]
        return 200, b"\x01\x01\x00\x00\x00\x00\x00\x01\x03"

    monkeypatch.setattr(ipp, "_post", post)
    assert ipp.get_printer_attributes("127.0.0.1") == {}
    assert ipp.print_job("127.0.0.1", b"pdf", "application/pdf", path="/printers/") == (0, None)
    assert paths == ["/ipp/print", "/", "/printers/", "/printers/"]
