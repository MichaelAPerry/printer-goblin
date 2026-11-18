# DEVLOG

| Date | Model | Task | Outcome |
|---|---|---|---|
| 2026-11-18 | claude | Prior-art survey, architecture, scope.py, safety.py, escpos.py, qr.py, notice.py | kept |
| 2026-11-18 | codex | net, discovery, identify, IPP/SNMP codecs, PS/PCL/PDF/receipt renderers, transports, verify, CLI, tests | kept; reviewed, 18/18 tests pass outside sandbox; added early cooldown check before confirmation prompt |
| 2026-11-18 | local (qwen3.5:9b) | Notice wording, remediation guide draft | kept with accuracy fixes (job-log claim, paper cut, public-IP refusal, PCI scope, TCP-only 631, baseline steps). MCP `ask_local` returned empty; called Ollama API directly with think=false |

## Next steps
- Test against real hardware: an IPP Everywhere office printer, a PCL-only laser, an Epson TM-series receipt printer (native `GS ( k` QR vs raster fallback).
- Optional mDNS/DNS-SD discovery (`_ipp._tcp`, `_pdl-datastream._tcp`).
- Decode the QR in CI (e.g. zbar) to verify the rendered payloads round-trip.
