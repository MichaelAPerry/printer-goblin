# DEVLOG

| Date | Model | Task | Outcome |
|---|---|---|---|
| 2026-11-18 | claude | Prior-art survey, architecture, scope.py, safety.py, escpos.py, qr.py, notice.py | kept |
| 2026-11-18 | codex | net, discovery, identify, IPP/SNMP codecs, PS/PCL/PDF/receipt renderers, transports, verify, CLI, tests | kept; reviewed, 18/18 tests pass outside sandbox; added early cooldown check before confirmation prompt |
| 2026-11-18 | local (qwen3.5:9b) | Notice wording, remediation guide draft | kept with accuracy fixes (job-log claim, paper cut, public-IP refusal, PCI scope, TCP-only 631, baseline steps). MCP `ask_local` returned empty; called Ollama API directly with think=false |
| 2026-11-18 | codex | Original mascot art via image generation; 1-bit PBM conversion (tools/make_assets.py) | kept; 384/576 px, ~20% ink |
| 2026-11-18 | codex | Fact sheet (findings.py), mascot in all renderers, 58/80mm paper, raster-QR fallback, workflow.py, loopback web GUI | kept; guardrail files untouched, GUI token/Host/Origin checks verified live; 38/38 tests |

| 2026-11-18 | local (qwen3.5:9b) | README and docs/about.md drafts | kept with accuracy fixes (removed fear-mongering opener, "ping"→ports, ethics/legal wording, audience, links) |
| 2026-11-18 | claude | No-arg launch opens GUI; B&W mascot; Pages + cross-platform test workflows | kept |
| 2026-11-18 | codex | PWG Raster renderer (sgray_8, 300 dpi), public-domain Fixed bitmap font, IPP Print-Job robustness | kept; CUPS round-trip exact; printed OK on Brother MFC-L2700DW (job 470, completed, 1 impression) |
| 2026-11-18 | claude | Live test vs Brother MFC-L2700DW from WSL | found+fixed: auto mode fell back to PCL with no evidence (would print garbage on host-based lasers); slow-waking printer ports mislabelled filtered (retry pass); WSL NAT source address shown as if real; verify output now human-readable |
| 2026-11-18 | codex | Correctness pass: verify policy/liveness verdicts, observed vs inferred findings, conservative ESC/POS, IPPS removed, print status ladder | kept; live: Brother EXPOSED (exit 3), unused IP INCONCLUSIVE (exit 4) |
| 2026-11-18 | codex | PyInstaller packaging + release workflow | kept; Claude built locally (sandbox had no PyPI): 7 MB Linux binary, GUI assets load, printed job 471 completed |
| 2026-11-18 | claude | Renamed Printer Gremlin -> Printer Goblin everywhere (package printer_goblin, CLI printer-goblin, state dir, assets) | kept; Pages URL unchanged so printed QR codes stay valid. Entries above use the old name |

| 2026-11-18 | codex | v0.2 paper-free assessment with IPP authorization checks, management reachability, TLS inspection, and firmware advisories | Working tree implementation and regression tests |

## Live test notes (2026-11-18, Brother MFC-L2700DW, home LAN, from WSL2)
- Advertises only image/urf + image/pwg-raster (sgray_8, 300 dpi), copies 1-99, SNMP public, ports 9100/631/515/80/443.
- First discovery after idle missed ports and once showed 9100/515 on the router (192.168.1.1) that were not open on re-test. Missed ports explained by printer deep sleep (now retried). The router reading is unexplained and not reproduced; treat as a WSL NAT artefact hypothesis, unconfirmed.

## Next steps
- Test against real hardware: an IPP Everywhere office printer, a PCL-only laser, an Epson TM-series receipt printer (native `GS ( k` QR vs raster fallback).
- Optional mDNS/DNS-SD discovery (`_ipp._tcp`, `_pdl-datastream._tcp`).
- Mascot is black-and-white everywhere (colour version dropped, 2026-11-18).
- Decode the QR in CI (e.g. zbar) to verify the rendered payloads round-trip.
- 2026-11-18 · claude · Review of v0.2 assessment: live run vs Brother MFC-L2700DW found Validate-Job OK (no auth), Telnet+FTP open, HTTPS 443 TLS 1.1 only. Fixes: TLSResult.modern (distinguish "legacy only"), strip ANSI/telnet IAC from banners, TELNET/FTP basis inferred, suppress IPP_NO_AUTH when UNAUTH_PRINT observed, replaced unverified advisory URLs with checked ones (Star Micronics dropped: no advisory page).
