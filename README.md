# Printer Gremlin 👹🖨️

**Printer security awareness and network segmentation testing, for authorized assessments only.**

Printer Gremlin shows that a printer can be reached from a network that shouldn't reach it. It prints one small notice, **"YOU'VE BEEN GOBBED!"**, with a QR code that links to a [remediation guide](docs/index.md). Then it checks the fix with a before/after reachability test.

Supports office printers (PostScript, PCL, PDF over raw 9100 or IPP) and thermal receipt printers (ESC/POS).

> ⚠️ Only use this on networks and devices you are authorized to test. Printer Gremlin refuses public IP addresses, limits how much it prints, and never sends cash-drawer or other peripheral-control commands. See [ARCHITECTURE.md](ARCHITECTURE.md#safety-design).

## Install

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e .            # Python ≥3.9; only dependency is segno
```

## Workflow

```bash
# 1. Find printer ports on an in-scope network (private ranges only, max /22, no data sent)
printer-gremlin discover 192.168.50.0/24

# 2. Identify a printer (IPP attributes, SNMP GET, HTTP title; nothing sent to port 9100)
printer-gremlin identify 192.168.50.23

# 3. Preview the notice locally (no network)
printer-gremlin preview --format pdf -o notice.pdf

# 4. Record reachability BEFORE the fix, from the segment that should be blocked
printer-gremlin baseline 192.168.50.23 --out before.json

# 5. Print ONE notice (requires the flag AND typing the address)
printer-gremlin demo 192.168.50.23 --yes-i-am-authorized --note "Q4 segmentation test"

# 6. After the fix, from the same place
printer-gremlin verify before.json     # exit 0 = PASS, 3 = still exposed
```

`demo --format auto` picks ESC/POS for receipt printers, PDF over IPP when the printer advertises it, otherwise PostScript or PCL over raw 9100. It refuses to guess for an unidentified device, so you need to pass `--format` yourself.

## Guardrails

| Guardrail | Limit |
|---|---|
| Scope | RFC 1918, RFC 6598, link-local, IPv6 ULA only; scans ≤ /22 |
| Confirmation | `--yes-i-am-authorized` + typed target address |
| Volume | 1 copy, 1 target per run, ≤3 jobs per run, 1 per printer per 10 min |
| ESC/POS | allowlisted builder: text, align, bold, size, feed, QR, raster, cut; no drawer, buzzer, or NV writes |
| Identification | IPP / SNMPv1 GET / HTTP GET only; no PJL, no SNMP SET |
| Audit | JSONL log of every attempt in `~/.local/state/printer-gremlin/` |

## Remediation guide

`docs/` is a GitHub Pages site (Settings → Pages → `main` / `docs`). Use `--guide-url` to point the QR code at your own copy.

## Development

```bash
pip install -e '.[dev]' && pytest -q
```

MIT licensed.
