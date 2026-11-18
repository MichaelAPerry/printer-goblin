import pytest

from printer_gremlin.payloads import pcl, pdf, postscript, receipt
from printer_gremlin.payloads.escpos import EscPosJob, UnsafeCommandError
from printer_gremlin.payloads.notice import Notice

NOTICE = Notice("You've been (gobbed)!", [r"One line with \ and ()."], "https://example.org/")


def test_receipt_allowlist_and_text_sanitization():
    data = receipt.render(NOTICE)
    assert b"\x1bp" not in data
    assert b"\x10\x14" not in data
    with pytest.raises(UnsafeCommandError):
        EscPosJob([("drawer", b"\x1bp\x00\x19\xfa")]).validate()
    assert EscPosJob().text("one\x1b\x00\r\t\x7f\ntwo").to_bytes() == b"one?????\ntwo"
    assert b"\x1dv0" in receipt.render(NOTICE, native_qr=False)


def test_native_qr_lengths():
    prefix = b"\x1d(k"
    sequence = EscPosJob().qr_native(NOTICE.url).to_bytes()
    functions = []
    lengths = []
    while sequence:
        assert sequence.startswith(prefix)
        length = int.from_bytes(sequence[3:5], "little")
        body, sequence = sequence[5:5 + length], sequence[5 + length:]
        assert len(body) == length and body[0] == 49
        functions.append(body[1])
        lengths.append(length)
    assert functions == [65, 67, 69, 80, 81]
    assert lengths == [4, 3, 3, len(NOTICE.url) + 3, 3]


def test_pdf_xref():
    data = pdf.render(NOTICE)
    offset = int(data.rsplit(b"startxref\n", 1)[1].splitlines()[0])
    header, count, free, *entries = data[offset:].splitlines()
    assert header == b"xref" and free.startswith(b"0000000000")
    for number, entry in enumerate(entries[:int(count.split()[1]) - 1], 1):
        object_offset = int(entry.split()[0])
        assert data[object_offset:].startswith(f"{number} 0 obj\n".encode())
    assert b"\\(gobbed\\)" in data


def test_ps_and_pcl_boundaries():
    ps = postscript.render(NOTICE)
    assert ps.startswith(b"%!PS-Adobe-3.0")
    assert ps.rstrip().endswith(b"showpage")
    assert b"\\(gobbed\\)" in ps
    data = pcl.render(NOTICE)
    assert data.startswith(b"\x1bE") and data.endswith(b"\x1bE")
    assert b"\x1b*t300R" in data and b"\x1b*r1A" in data and b"\x1b*rB" in data
