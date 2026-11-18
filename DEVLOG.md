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

## Next steps
- Test against real hardware: an IPP Everywhere office printer, a PCL-only laser, an Epson TM-series receipt printer (native `GS ( k` QR vs raster fallback).
- Optional mDNS/DNS-SD discovery (`_ipp._tcp`, `_pdl-datastream._tcp`).
- Mascot is black-and-white everywhere (colour version dropped, 2026-11-18).
- Decode the QR in CI (e.g. zbar) to verify the rendered payloads round-trip.
