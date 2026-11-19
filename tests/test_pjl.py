import re

import pytest

from printer_goblin.payloads import pjl
from printer_goblin.protocols import ipp


@pytest.mark.parametrize("fmt,language", [("ps", b"POSTSCRIPT"), ("pcl", b"PCL")])
def test_wrapper_uses_only_job_language_and_end_commands(fmt, language):
    data = pjl.wrap(b"PAYLOAD", fmt)
    commands = re.findall(rb"@PJL ([A-Z]+)", data.replace(b"PAYLOAD", b""))
    assert commands == [b"JOB", b"ENTER", b"EOJ"]
    assert b"@PJL ENTER LANGUAGE = " + language + b"\r\nPAYLOAD" + pjl.UEL in data
    for forbidden in (b"SET", b"DEFAULT", b"FS", b"RDYMSG", b"INQUIRE", b"DINQUIRE", b"INFO"):
        assert b"@PJL " + forbidden not in data


@pytest.mark.parametrize("fmt", ["pdf", "pwg", "escpos"])
def test_wrapper_refuses_other_formats(fmt):
    with pytest.raises(ValueError):
        pjl.wrap(b"x", fmt)


def test_ipp_query_falls_back_to_jetdirect_paths(monkeypatch):
    tried = []

    def fake_post(host, port, path, timeout, request):
        tried.append(path)
        return (404, b"") if path != "/ipp/port1" else (200, b"ok")

    monkeypatch.setattr(ipp, "_post", fake_post)
    monkeypatch.setattr(ipp, "_checked_response", lambda status, body: (0, {"printer-state": [3]}))
    attrs, path = ipp.query_printer("127.0.0.1")
    assert path == "/ipp/port1" and tried == ["/ipp/print", "/", "/printers/", "/ipp", "/ipp/port1"]
