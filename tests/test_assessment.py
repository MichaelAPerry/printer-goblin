import json
import ssl
import struct
from contextlib import nullcontext
from importlib import import_module

import pytest

from printer_goblin import advisories, cli
from printer_goblin.findings import findings
from printer_goblin.identify import Fingerprint, MGMT_PORTS
from printer_goblin.payloads import _page
from printer_goblin.payloads.notice import build_notice
from printer_goblin.protocols import ipp, tlsprobe

assessment = import_module("printer_goblin.identify")
HOST = "127.0.0.1"


def test_validate_job_operation_only(monkeypatch):
    def post(host, port, path, timeout, request):
        assert (host, port, path) == (HOST, 631, "/ipp/custom")
        assert struct.unpack_from(">BBHI", request) == (1, 1, 0x0004, 1)
        assert request[8] == 0x01
        offset = 9
        attrs = {}
        while request[offset] != 0x03:
            tag = request[offset]
            offset += 1
            fields = []
            for _ in range(2):
                size, = struct.unpack_from(">H", request, offset)
                offset += 2
                fields.append(request[offset:offset + size].decode())
                offset += size
            attrs[fields[0]] = (tag, fields[1])
        assert request[offset:] == b"\x03"
        assert attrs == {
            "attributes-charset": (0x47, "utf-8"),
            "attributes-natural-language": (0x48, "en"),
            "printer-uri": (0x45, f"ipp://{HOST}:631/ipp/custom"),
            "requesting-user-name": (0x42, "printer-goblin"),
            "document-format": (0x49, "image/pwg-raster"),
        }
        return 200, struct.pack(">BBHI", 1, 1, 0x0402, 1) + b"\x03"

    monkeypatch.setattr(ipp, "_post", post)
    assert ipp.validate_job(HOST, "image/pwg-raster", path="/ipp/custom") == 0x0402


def test_operations_supported_decodes_enum_and_integer():
    name = b"operations-supported"
    body = (b"\x01\x01\x00\x00\x00\x00\x00\x01\x04"
            b"\x23" + struct.pack(">H", len(name)) + name + b"\x00\x04\x00\x00\x00\x04"
            b"\x21\x00\x00\x00\x04\x00\x00\x00\x0b\x03")
    assert ipp.decode_response(body)["operations-supported"] == [4, 11]


@pytest.mark.parametrize("status,expected", [
    (0, ["UNAUTH_PRINT"]), (0xFF, ["UNAUTH_PRINT"]), (0x0100, []),
    (0x0401, ["IPP_AUTH_REQUIRED"]), (0x0402, ["IPP_AUTH_REQUIRED"]),
    (0x0403, ["IPP_AUTH_REQUIRED"]), (0x040A, []), (None, []),
])
def test_status_findings(status, expected):
    fp = Fingerprint(HOST, validate_job_status=status)
    report = findings(fp, HOST)
    assert [item.id for item in report] == expected
    assert all(item.basis == "observed" for item in report)


@pytest.mark.parametrize("auth,security,scheme,expect_auth,note", [
    (["none", "none"], ["none", "none"], "ipp", True, "No TLS advertised"),
    (["none", "basic"], ["none", "tls"], "ipp", False, "TLS is advertised"),
    (["none"], ["none", "none"], "ipps", False, "TLS is advertised"),
    (["none", "none"], ["none", "none", "tls"], "ipp", True, "No TLS advertised"),
])
def test_paired_ipp_attributes(auth, security, scheme, expect_auth, note):
    fp = Fingerprint(HOST, ipp_ok=True, ipp_attrs={
        "printer-uri-supported": ["ipp://printer/one", f"{scheme}://printer/two"],
        "uri-authentication-supported": auth, "uri-security-supported": security,
    })
    report = {item.id: item for item in findings(fp, HOST)}
    assert ("IPP_NO_AUTH" in report) == expect_auth
    assert note in report["IPP_PLAIN"].detail
    assert "IPP_NO_TLS" not in report


@pytest.mark.parametrize("enabled,operations,formats,expected", [
    (True, [4], ["application/pdf"], 0x0401),
    (True, [11], ["application/pdf"], None),
    (True, [4], [], None),
    (False, [4], ["application/pdf"], None),
])
def test_identify_assessment_is_paper_free(monkeypatch, tmp_path, enabled, operations, formats, expected):
    connected = []
    sent = []

    class Connection:
        def __init__(self, port):
            self.port = port

        def settimeout(self, timeout):
            assert 0 < timeout <= 2

        def recv(self, size):
            assert self.port in (21, 23)
            assert size == 512
            return b"\x00\xff\r\n Server " + b"!" * 140

        def sendall(self, data):
            sent.append((self.port, data))

    def connect(address, timeout=None):
        host, port = address
        assert host == HOST
        connected.append(port)
        if port not in (21, 23, 631, 9100):
            raise ConnectionRefusedError(111, "closed")
        return nullcontext(Connection(port))

    monkeypatch.setenv("PRINTER_GOBLIN_STATE", str(tmp_path))
    monkeypatch.setattr(assessment.socket, "create_connection", connect)
    monkeypatch.setattr(assessment.snmp, "probe_printer", lambda _host: ({}, False))
    monkeypatch.setattr(tlsprobe, "probe", lambda _host, port: tlsprobe.TLSResult(version="TLSv1.3"))
    monkeypatch.setattr(ipp, "query_printer", lambda _host, timeout: ({
        "operations-supported": operations, "document-format-supported": formats,
    }, "/ipp/custom"))

    def validate(host, document_format, *, path, timeout):
        assert (host, document_format, path) == (HOST, "application/pdf", "/ipp/custom")
        return 0x0401

    monkeypatch.setattr(ipp, "validate_job", validate)
    fp = assessment.identify(HOST, validate_job=enabled)
    assert connected.count(9100) == 1
    assert not sent
    assert fp.mgmt_ports == [21, 23]
    assert fp.banners == dict.fromkeys((21, 23), "Server " + "!" * 113)
    assert "TCP 631 also negotiated TLS." in next(
        item.detail for item in findings(fp, HOST) if item.id == "IPP_PLAIN")
    assert fp.validate_job_status == expected
    audit = tmp_path / "audit.log"
    if expected is None:
        assert not audit.exists()
    else:
        entry = json.loads(audit.read_text())
        assert (entry["event"], entry["target"], entry["status"]) == ("validate-job", HOST, expected)


@pytest.mark.parametrize("legacy_outcome,expected", [
    (None, "accepted"),
    ("TLSV1_ALERT_PROTOCOL_VERSION", "refused"),
    ("NO_PROTOCOLS_AVAILABLE", "untestable"),
])
def test_tls_handshake_only(monkeypatch, legacy_outcome, expected):
    contexts = []
    # Minimal synthetic Certificate/TBSCertificate shape containing an expired UTCTime.
    def field(tag, data):
        return bytes((tag, len(data))) + data

    name = field(0x30, b"name")
    validity = field(0x30, field(0x17, b"000101000000Z") + field(0x17, b"010101000000Z"))
    cert = field(0x30, field(0x30, field(2, b"\x01") + field(0x30, b"") + name + validity + name))

    class Peer:
        def version(self):
            return "TLSv1.3"

        def cipher(self):
            return ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)

        def getpeercert(self, *, binary_form):
            assert binary_form
            return cert

    class Context:
        def __init__(self, protocol):
            assert protocol == ssl.PROTOCOL_TLS_CLIENT
            contexts.append(self)

        def set_ciphers(self, ciphers):
            assert ciphers == "DEFAULT:@SECLEVEL=0"

        def wrap_socket(self, sock, *, server_hostname):
            assert not self.check_hostname and self.verify_mode == ssl.CERT_NONE
            assert server_hostname == HOST
            if len(contexts) == 2 and legacy_outcome:
                exc = ssl.SSLError()
                exc.reason = legacy_outcome
                raise exc
            return nullcontext(Peer())

    class Socket:
        def settimeout(self, timeout):
            assert 0 < timeout <= 3

    def connect(address, timeout):
        assert address == (HOST, 8443)
        assert timeout == 3
        return nullcontext(Socket())

    monkeypatch.setattr(tlsprobe.ssl, "SSLContext", Context)
    monkeypatch.setattr(tlsprobe.socket, "create_connection", connect)
    result = tlsprobe.probe(HOST, 8443, timeout=10)
    assert contexts[1].maximum_version == ssl.TLSVersion.TLSv1_1
    assert contexts[1].minimum_version == ssl.TLSVersion.TLSv1
    assert result.version == "TLSv1.3"
    assert result.cipher == "TLS_AES_256_GCM_SHA384"
    assert result.self_signed and result.expired
    assert result.not_after == "2001-01-01T00:00:00+00:00"
    report = findings(Fingerprint(HOST, tls={8443: result}), HOST)
    assert bool(report) == (expected == "accepted")
    assert result.legacy == expected


def test_findings_order_and_fact_sheet_fit():
    fp = Fingerprint(HOST, [9100, 443, 631, 515, 80, *MGMT_PORTS], ipp_ok=True,
                     snmp_ok=True, http_ok=True, firmware="1.2.3", validate_job_status=0)
    report = findings(fp, HOST)
    assert [item.severity for item in report] == sorted(
        (item.severity for item in report), key=["high", "medium", "low", "info"].index)
    refs = {item.id: item.ref for item in report}
    assert refs["RAW9100"] == "raw-9100"
    assert refs["UNAUTH_PRINT"] == "unauth-print"
    assert refs["FIRMWARE"] == "firmware"
    notice = build_notice(HOST, 9100, "raw", HOST, fingerprint=fp)
    assert notice.findings == report
    assert sum(line.startswith("[") for line in notice.fact_lines()) == 6
    assert report[0].title in notice.fact_lines()[-12]
    assert len(notice.services) == 5
    _page.layout(notice, _page.page_mascot(notice))


def test_cli_opt_out_and_json(monkeypatch, capsys):
    def probe(target, *, validate_job):
        assert not validate_job
        return Fingerprint(target, ports=[21], mgmt_ports=[21], banners={21: "FTP"},
                           tls={631: tlsprobe.TLSResult(legacy="refused")})

    monkeypatch.setattr(cli, "identify", probe)
    assert cli.main(["identify", HOST, "--no-validate-job", "--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["validate_job_status"] is None
    assert report["banners"] == {"21": "FTP"}
    assert report["tls"]["631"]["legacy"] == "refused"


def test_vendor_advisory_lookup():
    assert advisories.vendor_advisory_url(" hewlett-packard LaserJet") == (
        advisories.vendor_advisory_url("HP LaserJet"))
    assert advisories.vendor_advisory_url("Unknown") is None


def test_discovery_fingerprint_skips_assessment(monkeypatch):
    def connect_ports(pairs, timeout):
        assert [port for _, port in pairs] == list(assessment.DEFAULT_PORTS)
        return {pair: "open" if pair[1] in (631, 443) else "closed" for pair in pairs}

    def unexpected(*args, **kwargs):
        pytest.fail("discovery ran an assessment check")

    monkeypatch.setattr(assessment.net, "probe_with_retry", connect_ports)
    monkeypatch.setattr(assessment.snmp, "probe_printer", lambda _host: ({}, False))
    monkeypatch.setattr(ipp, "query_printer", lambda _host, timeout: ({
        "operations-supported": [4], "document-format-supported": ["application/pdf"],
    }, "/ipp/print"))
    monkeypatch.setattr(ipp, "validate_job", unexpected)
    monkeypatch.setattr(tlsprobe, "probe", unexpected)
    fp = assessment.identify(HOST, assess=False)
    assert fp.ipp_ok and not fp.mgmt_ports and not fp.tls
