import struct
from dataclasses import replace

import pytest

from printer_goblin import cli, net, safety, workflow
from printer_goblin.identify import Fingerprint
from printer_goblin.payloads import _page, pwg
from printer_goblin.payloads.notice import build_notice
from printer_goblin.protocols import ipp
from tools.pwg_to_png import decode_rows, to_png


def test_letter_header_and_pixels():
    notice = build_notice("192.168.1.20", 631, "ipp", "192.168.2.30")
    data = pwg.render(notice)
    assert len(data) < safety.MAX_PAYLOAD_BYTES // 2
    assert data[:4] == b"RaS2"
    header = data[4:1800]
    assert len(header) == 1796
    assert header[:64] == b"PwgRaster".ljust(64, b"\0")
    assert header[284:300] == bytes(16)  # Reserved legacy ImagingBoundingBox.
    assert header[1732:] == b"na_letter_8.5x11in".ljust(64, b"\0")

    def fields(offset, count):
        return struct.unpack_from(f">{count}I", header, offset)

    assert fields(276, 2) == (300, 300)
    assert fields(340, 1) == (1,)
    assert fields(352, 2) == (612, 792)
    assert fields(372, 2) == (2550, 3300)
    assert fields(384, 5) == (8, 8, 2550, 0, 18)
    assert fields(420, 1) == (1,)
    assert fields(452, 3) == (1, 1, 1)
    assert fields(484, 1) == (0,)

    rows = list(decode_rows(data[1800:], 2550, 3300))
    assert len(rows) == 3300 and all(len(row) == 2550 for row in rows)
    assert sum(row.count(255) for row in rows) > 0.9 * 2550 * 3300
    ink_rows = [(y, row) for y, row in enumerate(rows) if b"\0" in row]
    assert fields(464, 4) == (
        min(row.index(0) for _, row in ink_rows), ink_rows[0][0],
        max(row.rindex(0) for _, row in ink_rows) + 1, ink_rows[-1][0] + 1,
    )

    _, _, top, qr = _page.layout(notice, _page.page_mascot(notice))
    left, top = 150, round(top * 300 / 72)
    module = 480 // len(qr)
    assert any(any(row) for row in qr)
    for y, row in enumerate(qr):
        for x, dark in enumerate(row):
            pixel = bytes([0 if dark else 255])
            assert rows[top + y * module][left + x * module:left + (x + 1) * module] == pixel * module

    png = to_png(data)
    assert png[:8] == b"\x89PNG\r\n\x1a\n"
    assert struct.unpack_from(">2I", png, 16) == (638, 825)


@pytest.mark.parametrize(("line", "encoded"), [
    (b"\xff" * 2550, b"\x7f\xff" * 19 + b"\x75\xff"),
    (b"\0\xff" * 4, b"\xf9" + b"\0\xff" * 4),
    (bytes(range(256)) + b"\0", b"\x81" + bytes(range(128))
     + b"\x81" + bytes(range(128, 256)) + b"\0\0"),
])
def test_line_encoding(line, encoded):
    assert pwg._encode_line(line) == encoded
    assert list(decode_rows(b"\0" + encoded, len(line), 1)) == [line]


def test_line_repeat_groups():
    row = b"\xff" * 128
    other = b"\0" * 128
    pixels = bytearray(row * 514 + other)
    compressed = pwg._encode_raster(pixels, len(row))
    assert compressed == b"\xff\x7f\xff" * 2 + b"\x01\x7f\xff\x00\x7f\x00"
    assert list(decode_rows(compressed, 128, 515)) == [row] * 514 + [other]


def test_auto_selection_and_raw_refusal(monkeypatch):
    ip = "192.168.1.20"
    fp = Fingerprint(ip, kind="office", ports=[631, 9100], languages=["urf", "pwg-raster"])
    assert workflow._select_job(fp, "auto", None) == ("pwg", "ipp")
    with pytest.raises(safety.PrintRefused, match="none advertised"):
        workflow._select_job(replace(fp, languages=[]), "auto", None)
    monkeypatch.setattr(workflow, "fingerprint_target", lambda _: fp)
    with pytest.raises(safety.PrintRefused, match="requires IPP"):
        workflow.plan_print(ip, "pwg", "raw")


def test_a4_preview(tmp_path):
    output = tmp_path / "notice.pwg"
    assert cli.main(["preview", "--format", "pwg", "--media", "a4", "-o", str(output)]) == 0
    data = output.read_bytes()
    assert struct.unpack_from(">2I", data, 4 + 352) == (595, 842)
    assert struct.unpack_from(">2I", data, 4 + 372) == (2480, 3507)
    assert data[4 + 1732:].startswith(b"iso_a4_210x297mm\0")


def test_pwg_print_job_uses_media_and_accepts_substitution(monkeypatch, tmp_path):
    ip = "192.168.1.20"
    fp = Fingerprint(ip, kind="office", ports=[631], languages=["urf", "pwg-raster"],
                     ipp_attrs={"media-default": ["iso_a4_210x297mm"]}, ipp_path="/printer")
    monkeypatch.setattr(workflow, "fingerprint_target", lambda _: fp)
    monkeypatch.setattr(net, "source_ip", lambda _: "192.168.2.30")
    plan = workflow.plan_print(ip)
    assert "media-default" in ipp.REQUESTED_ATTRIBUTES
    assert struct.unpack_from(">2I", plan.data, 4 + 352) == (595, 842)

    class Connection:
        def __init__(self, host, port, timeout):
            assert (host, port) == (ip, 631)
            assert timeout >= 30

        def request(self, method, path, body, headers):
            assert (method, path) == ("POST", "/printer")
            assert int(headers["Content-Length"]) == len(body)
            assert "Transfer-Encoding" not in headers
            assert body.endswith(b"\x03" + plan.data)
            attributes = ipp.decode_response(body)
            assert attributes["document-format"] == ["image/pwg-raster"]
            assert attributes["copies"] == [1]

        def getresponse(self):
            return self

        status = 200

        def read(self, limit):
            return bytes.fromhex("0101000100000001") + b"\x02\x21\x00\x06job-id\x00\x04\x00\x00\x00\x07\x03"

        def close(self):
            pass

    monkeypatch.setattr(ipp.http.client, "HTTPConnection", Connection)
    monkeypatch.setattr(ipp, "get_job_attributes", lambda *args, **kwargs: {"job-state": [9]})
    governor = safety.PrintGovernor(directory=tmp_path)
    with pytest.raises(safety.PrintRefused, match="requires IPP"):
        workflow.execute_print(replace(plan, protocol="raw"), ip, True, governor)
    result = workflow.execute_print(plan, ip, True, governor)
    assert (result["status"], result["ipp_status"], result["job_id"]) == ("completed", 1, 7)
