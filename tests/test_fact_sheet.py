from pathlib import Path

import pytest

from printer_gremlin import assets
from printer_gremlin.findings import findings
from printer_gremlin.identify import Fingerprint
from printer_gremlin.payloads import _page, pcl, pdf, postscript, receipt
from printer_gremlin.payloads.notice import build_notice

PIXELS = [[True, False, True], [False, True, False]]
ALL_PORTS = [9100, 631, 515, 80, 443]


@pytest.mark.parametrize("field,value,expected", [
    ("ports", [9100], ["RAW9100"]),
    ("ports", [631, 80], []),
    ("ipp_ok", True, ["IPP_PLAIN"]),
    ("ports", [515], ["LPD"]),
    ("snmp_ok", True, ["SNMP_PUBLIC"]),
    ("http_ok", True, ["HTTP_ADMIN"]),
    ("ports", [443], ["HTTPS_ADMIN"]),
])
def test_observed_findings(field, value, expected):
    fp = Fingerprint("127.0.0.1", **{field: value})
    assert [item.id for item in findings(fp, fp.ip)] == expected


def test_findings_order_and_basis():
    ip = "127.0.0.1"
    fp = Fingerprint(ip, ALL_PORTS, ipp_ok=True, snmp_ok=True, http_ok=True)
    report = findings(fp, ip)
    assert [item.id for item in report] == [
        "RAW9100", "IPP_PLAIN", "LPD", "SNMP_PUBLIC", "HTTP_ADMIN", "HTTPS_ADMIN",
    ]
    assert [item.severity for item in report] == ["high", *["medium"] * 4, "info"]
    assert all(len(item.title) <= 32 and len(item.detail) <= 64 for item in report)
    assert [item.basis for item in report] == [
        "inferred", "observed", "inferred", "observed", "inferred", "observed",
    ]
    assert all(item.detail.startswith("Likely: ") == (item.basis == "inferred") for item in report)
    assert findings(Fingerprint(ip), ip) == []


def test_load_pbm(monkeypatch):
    monkeypatch.setattr(assets, "ASSET_DIR", Path(__file__).with_name("fixtures"))
    assert assets.load_pbm("mascot-p1.pbm") == PIXELS
    assert assets.load_pbm("mascot-p4.pbm") == PIXELS
    assert assets.load_pbm("absent.pbm") is None
    assert assets.mascot(300) is None


def test_mascot_downscale(monkeypatch):
    calls = []
    rows = [[x % 2 == y % 2 for x in range(576)] for y in range(6)]

    def load(name):
        calls.append(name)
        return rows if name == "gremlin_576.pbm" else None

    monkeypatch.setattr(assets, "load_pbm", load)
    assert assets.mascot(288) == [[True] * 288] * 3
    assert calls == ["gremlin_384.pbm", "gremlin_576.pbm"]


@pytest.mark.parametrize("image", [None, PIXELS])
def test_fact_sheet_renderers(monkeypatch, image):
    monkeypatch.setattr(_page, "mascot", lambda width: image)
    monkeypatch.setattr(receipt, "mascot", lambda width: image)
    serial = "PRIVATE-SERIAL-123456789"
    fp = Fingerprint("127.0.0.1", ALL_PORTS, {
        "printer-make-and-model": [f"Sample printer {serial}"],
        "printer-serial-number": [serial],
    }, {"prtGeneralSerialNumber": "OTHER-PRIVATE-SERIAL"}, kind="office",
        firmware="Firmware OTHER-PRIVATE-SERIAL", ipp_ok=True, snmp_ok=True, http_ok=True)
    notice = build_notice(fp.ip, 9100, "raw", fp.ip, fingerprint=fp)
    ps, pcl_data, pdf_data = (renderer.render(notice) for renderer in (postscript, pcl, pdf))
    esc = receipt.render(notice, paper="58", native_qr=False)
    for data in (ps, pcl_data, pdf_data, esc):
        assert b"WHAT THE GREMLIN SAW" in data
        assert b"[HIGH]" in data and b"Likely: " in data
        assert serial.encode() not in data
        assert b"OTHER-PRIVATE-SERIAL" not in data
    assert ps.startswith(b"%!PS") and ps.rstrip().endswith(b"showpage")
    assert (b"imagemask" in ps) == bool(image)
    assert pcl_data.startswith(b"\x1bE") and pcl_data.endswith(b"\x1bE")
    assert pcl_data.count(b"\x1b*r1A") == (2 if image else 1)
    assert (b"/ImageMask true" in pdf_data) == bool(image)
    xref = int(pdf_data.rsplit(b"startxref\n", 1)[1].splitlines()[0])
    header, count, _, *entries = pdf_data[xref:].splitlines()
    assert header == b"xref"
    for number, entry in enumerate(entries[:int(count.split()[1]) - 1], 1):
        assert pdf_data[int(entry.split()[0]):].startswith(f"{number} 0 obj\n".encode())
    assert b"\x1bp" not in esc and b"\x10\x14" not in esc
    widths = [int.from_bytes(raster[1:3], "little") * 8 for raster in esc.split(b"\x1dv0")[1:]]
    assert len(widths) == (2 if image else 1)
    assert all(0 < width <= 384 for width in widths)


def test_identify_records_responses_and_firmware(monkeypatch):
    from printer_gremlin.identify import identify, ipp, net, snmp

    class Connection:
        def __init__(self, ip, port, timeout):
            assert (ip, port) == ("127.0.0.1", 80)

        def request(self, method, path):
            assert (method, path) == ("GET", "/")

        def getresponse(self):
            # A login challenge is evidence of HTTP even without a usable title.
            return type("Response", (), {"status": 401})()

        def close(self):
            pass

    monkeypatch.setattr(net, "tcp_open", lambda ip, port, timeout, accurate=False: "open")
    monkeypatch.setattr("http.client.HTTPConnection", Connection)
    monkeypatch.setattr(snmp, "probe_printer", lambda ip: ({}, True))
    monkeypatch.setattr(ipp, "query_printer", lambda ip, timeout: (
        {"printer-firmware-version": [b"1.2.3"]}, "/ipp/print"
    ))
    fp = identify("127.0.0.1")
    assert fp.ipp_ok and fp.firmware == "1.2.3"
    assert fp.snmp_ok and not fp.snmp_values
    assert fp.http_ok and fp.http_title is None


def test_preview_sample_is_opt_in(tmp_path):
    from printer_gremlin.cli import main

    path = tmp_path / "notice.pdf"
    args = ["preview", "--format", "pdf", "-o", str(path)]
    assert main(args) == 0
    assert b"not identified" in path.read_bytes()
    assert main([*args, "--sample"]) == 0
    payload = path.read_bytes()
    assert b"sample identification data" in payload and b"[HIGH]" in payload


@pytest.mark.parametrize("model,expected", [
    ("Star TSP650", False),
    ("Star TSP650 compatible with TM-T88", False),
    ("Star mC-Print3", False),
    ("Bixolon SRP-350", False),
    ("Citizen CT-S310", False),
    ("XPrinter XP-80", False),
    ("Rongta", False),
    ("Generic thermal receipt printer", False),
    ("Epson TM-T88", True),
    ("TM-T88V", True),
    ("XPrinter with ESC/POS emulation", True),
])
def test_thermal_requires_positive_escpos_evidence(model, expected):
    from printer_gremlin import safety, workflow
    from printer_gremlin.identify import _add_evidence

    fp = Fingerprint("127.0.0.1", snmp_values={"sysDescr": model})
    _add_evidence(fp)
    assert fp.kind == "thermal"
    assert ("escpos" in fp.languages) is expected
    if expected:
        assert workflow._select_job(fp, "auto", None) == ("escpos", "raw")
    else:
        with pytest.raises(safety.PrintRefused, match="command language is unconfirmed"):
            workflow._select_job(fp, "auto", None)
        assert workflow._select_job(fp, "escpos", None) == ("escpos", "raw")
