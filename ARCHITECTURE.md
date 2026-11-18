# Architecture

## Prior art (surveyed 2026-11-18)

| Project | What it does | Why we didn't build on it |
|---|---|---|
| [PRET](https://github.com/RUB-NDS/PRET) (RUB-NDS) | Interactive PostScript/PJL/PCL exploitation shell; checks language support via IPP, HTTP and SNMP | Built for attacks (file system access, NVRAM, DoS). We borrow the idea of fingerprinting via IPP/SNMP/HTTP before choosing a language, but none of the attack surface. Needs ImageMagick/Ghostscript. |
| [python-escpos](https://python-escpos.readthedocs.io/) | Full ESC/POS driver | Exposes `cashdraw()` (ESC p pulse) and NV-memory commands. We wrote a ~150-line allowlisted builder instead so drawer kicks are impossible by construction. |
| [pyipp](https://pypi.org/project/pyipp/) / [ippx](https://pypi.org/project/ippx/) | IPP clients | Async + aiohttp/httpx dependencies. We need only two operations (Get-Printer-Attributes, Print-Job), so a stdlib codec stays small and auditable. |
| nmap NSE (`snmp-sysdescr`, `http-title`, port 9100 probes) | General scanning | Great for discovery, but it is a separate install and some printer scripts send PJL to 9100, which prints garbage on receipt printers. |

Dependency budget: Python ≥3.9 standard library + [`segno`](https://pypi.org/project/segno/) (pure-Python QR generation).

## Modules

```
printer_gremlin/
  scope.py        private/link-local only; scans capped at /22; DNS can't smuggle public targets
  safety.py       typed-address confirmation, 3 prints/run, 10-min per-target cooldown, audit log
  net.py          TCP connect probes (open / closed / filtered), bounded concurrency
  discovery.py    port sweep of an in-scope CIDR; sends no application data
  identify.py     IPP Get-Printer-Attributes + SNMPv1 GET + HTTP <title>; classifies office vs thermal
  protocols/ipp.py   minimal RFC 8010 codec
  protocols/snmp.py  minimal SNMPv1 GET (read-only, never SET)
  payloads/
    notice.py     printer-independent notice content
    qr.py         QR matrix via segno
    postscript.py / pcl.py / pdf.py   one-page office renderers, no external resources
    escpos.py     allowlisted ESC/POS builder
    receipt.py    notice -> ESC/POS
  transports.py   raw 9100 (AppSocket/JetDirect) and IPP Print-Job
  verify.py       before/after reachability baseline and comparison
  cli.py          discover / identify / preview / demo / baseline / verify
```

## Safety design

* **Scope:** RFC 1918, RFC 6598, link-local and IPv6 ULA/link-local only. Not configurable from the CLI.
* **No PJL and nothing sent to 9100 during identification.** Raw bytes on a receipt printer print as paper-wasting garbage, so identification uses only IPP, SNMP GET and HTTP GET.
* **Unknown device + auto format = refuse.** The operator must choose a format explicitly.
* **ESC/POS allowlist:** init, align, bold, size, feed, QR (`GS ( k` functions 65/67/69/80/81 only), raster image, paper cut. Text segments are stripped of control bytes. Not emitted: `ESC p`, `DLE DC4`, buzzer, NV writes, panel lock.
* **Volume:** one copy per job, never sets a copy count, ≤3 jobs per run, 1 per target per 10 minutes, one target per `demo`.
* **Audit:** every attempt (allowed or refused) is written as JSONL to the state directory.

## Verification semantics

`baseline` records TCP reachability (open/closed/filtered) from the current host. `verify` re-probes the same host/ports and reports `isolated`, `STILL EXPOSED`, `newly exposed`, or `unchanged-closed`. A result only applies to the network position it was run from, so run both from the segment that should be blocked.
