import re
from pathlib import Path

import pytest

from printer_goblin.findings import Finding, findings
from printer_goblin.identify import Fingerprint
from printer_goblin.payloads.notice import DEFAULT_GUIDE_URL, build_notice, guide_link

ROOT = Path(__file__).resolve().parents[1]
FINDINGS_SOURCE = ROOT / "printer_goblin" / "findings.py"
FINDINGS_DOC = ROOT / "docs" / "findings.md"
CUSTOM_GUIDE = "https://guide.example.org/fix/"
IP = "192.0.2.44"
MODEL = "Acme Model X9000"
SERIAL = "SN-SECRET-42"


def test_guide_link_default_guide():
    assert guide_link("raw-9100") == "https://michaelaperry.github.io/printer-goblin/findings/#raw-9100"
    assert guide_link("ipp-plain") == DEFAULT_GUIDE_URL + "findings/#ipp-plain"


@pytest.mark.parametrize("ref", [None, "", "x y", "../a", "Raw-9100", "a/b", "a#b", "a\n"])
def test_guide_link_bad_ref_returns_base(ref):
    assert guide_link(ref) == DEFAULT_GUIDE_URL


def test_guide_link_custom_guide_is_never_altered():
    assert guide_link("raw-9100", CUSTOM_GUIDE) == CUSTOM_GUIDE
    assert guide_link("x y", CUSTOM_GUIDE) == CUSTOM_GUIDE


def test_build_notice_links_most_severe_finding():
    # LPD (medium, observed first) and TELNET (high, management port) -> TELNET wins.
    fp = Fingerprint(IP, ports=[515, 23])
    notice = build_notice(IP, 515, "raw", IP, fingerprint=fp)
    assert [item.id for item in notice.findings] == ["TELNET", "LPD"]
    assert notice.url == DEFAULT_GUIDE_URL + "findings/#telnet"


def test_build_notice_without_findings_uses_guide_url():
    notice = build_notice(IP, 9100, "raw", IP, guide_url=CUSTOM_GUIDE, fingerprint=Fingerprint(IP))
    assert notice.findings == []
    assert notice.url == CUSTOM_GUIDE
    assert build_notice(IP, 9100, "raw", IP).url == DEFAULT_GUIDE_URL


def test_build_notice_custom_guide_with_findings_is_unchanged():
    fp = Fingerprint(IP, ports=[9100])
    assert build_notice(IP, 9100, "raw", IP, CUSTOM_GUIDE, fingerprint=fp).url == CUSTOM_GUIDE


def test_raw9100_deeplink_has_no_private_data():
    fp = Fingerprint(IP, ports=[9100], kind="office",
                     ipp_attrs={"printer-make-and-model": [MODEL],
                                "printer-serial-number": [SERIAL]})
    notice = build_notice(IP, 9100, "raw", IP, fingerprint=fp)
    assert notice.url == "https://michaelaperry.github.io/printer-goblin/findings/#raw-9100"
    for private in (IP, MODEL, SERIAL, "Acme", "X9000"):
        assert private not in notice.url


def _finding_ids() -> list[str]:
    ids = re.findall(r'Finding\(\s*"([A-Z0-9_]+)"', FINDINGS_SOURCE.read_text())
    assert ids, "no Finding(...) ids found in findings.py"
    return sorted(set(ids))


def test_every_emittable_ref_is_well_formed():
    refs = {Finding(fid, "info", "t", "d", "observed").ref for fid in _finding_ids()}
    assert "raw-9100" in refs
    for ref in refs:
        assert re.fullmatch(r"[a-z0-9-]+", ref), ref
        assert guide_link(ref) == DEFAULT_GUIDE_URL + "findings/#" + ref


@pytest.mark.skipif(not FINDINGS_DOC.exists(), reason="docs/findings.md not written yet")
def test_every_emittable_ref_has_a_doc_anchor():
    text = FINDINGS_DOC.read_text()
    missing = [fid for fid in _finding_ids()
               if "{#%s}" % Finding(fid, "info", "t", "d", "observed").ref not in text]
    assert not missing, f"docs/findings.md lacks anchors for: {missing}"


def test_printed_finding_lines_fit_and_never_cut_mid_word():
    fp = Fingerprint(IP, ports=[9100, 631, 515, 80], kind="office", ipp_ok=True,
                     validate_job_status=0, firmware="1.0")
    notice = build_notice(IP, 9100, "raw", "10.0.0.0/24", fingerprint=fp)
    assert notice.findings, "expected findings for an open printer"
    lines = notice.fact_lines()
    for finding in notice.findings[:6]:
        if finding.id == "FIRMWARE":
            continue
        printed = next(line for line in lines if line == finding.detail or line.endswith("...")
                       and finding.detail.startswith(line[:-3]))
        assert len(printed) <= 84
        if printed != finding.detail:
            # A shortened line stops at a word boundary.
            assert finding.detail[len(printed) - 3] == " "
    long = Finding("X", "high", "t", "word " * 30, "observed")
    notice.findings = [long]
    assert notice.fact_lines()[-1].endswith("...") and len(notice.fact_lines()[-1]) <= 84
