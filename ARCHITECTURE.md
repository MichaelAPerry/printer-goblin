# Architecture

## Prior art (surveyed 2026-11-18)

| Project | What it does | Why we didn't build on it |
|---|---|---|
| [PRET](https://github.com/RUB-NDS/PRET) (RUB-NDS) | Interactive PostScript/PJL/PCL exploitation shell; checks language support via IPP, HTTP and SNMP | Built for attacks (file system access, NVRAM, DoS). We borrow the idea of fingerprinting via IPP/SNMP/HTTP before choosing a language, but none of the attack surface. Needs ImageMagick/Ghostscript. |
| [python-escpos](https://python-escpos.readthedocs.io/) | Full ESC/POS driver | Exposes `cashdraw()` (ESC p pulse) and NV-memory commands. We wrote a ~150-line allowlisted builder instead so drawer kicks are impossible by construction. |
| [pyipp](https://pypi.org/project/pyipp/) / [ippx](https://pypi.org/project/ippx/) | IPP clients | Async + aiohttp/httpx dependencies. We need only four operations (Get-Printer-Attributes, Validate-Job, Print-Job, Get-Job-Attributes), so a stdlib codec stays small and auditable. |
| nmap NSE (`snmp-sysdescr`, `http-title`, port 9100 probes) | General scanning | Great for discovery, but it is a separate install and some printer scripts send PJL to 9100, which prints garbage on receipt printers. |

Dependency budget: Python ≥3.10 standard library + [`segno`](https://pypi.org/project/segno/) (pure-Python QR generation).

## Modules

```
printer_goblin/
  scope.py        private/link-local only; scans capped at /22; DNS can't smuggle public targets
  safety.py       typed-address confirmation, 3 prints/run, 10-min per-target cooldown, audit log
  net.py          TCP connect probes (open / closed / filtered), bounded concurrency
  discovery.py    port sweep of an in-scope CIDR; sends no application data
  identify.py     paper-free IPP, SNMP, HTTP, TLS and management-port assessment; classifies office vs thermal
  findings.py     severity-tagged findings from observed probe evidence
  advisories.py   vendor security advisory links for reported firmware
  assets.py       packaged PBM parsing and mascot scaling
  protocols/ipp.py   minimal RFC 8010 codec
  protocols/snmp.py  minimal SNMPv1 GET (read-only, never SET)
  protocols/tlsprobe.py  handshake-only TLS version, cipher, and certificate inspection
  payloads/
    notice.py     printer-independent notice and serial-free fact sheet
    qr.py         QR matrix via segno
    postscript.py / pcl.py / pdf.py / pwg.py   one-page office renderers, no external resources
    escpos.py     allowlisted ESC/POS builder
    receipt.py    notice -> ESC/POS
  transports.py   raw 9100 (AppSocket/JetDirect) and IPP Print-Job
  verify.py       before/after reachability baseline and comparison
  report.py       paper-free assessment, serial masking, evidence digest, and HTML/Markdown export
  workflow.py     shared assessment, rendering plans, guarded submission, and audit
  gui/            loopback HTTP server, token-protected API, and static browser interface
  cli.py          discover / identify / report / preview / demo / baseline / snapshot / verify / gui
```

## Safety design

* **Scope:** RFC 1918, RFC 6598, link-local and IPv6 ULA/link-local only. Not configurable from the CLI.
* **No PJL and nothing sent to 9100 during identification.** Raw 9100 is checked with TCP connect alone. Identification uses the existing SNMP GET with community `public` and HTTP GET without credentials.
* **IPP Validate-Job:** Used only when the printer advertises the operation and a document format. RFC 8011 validation sends operation attributes alone and creates no job. Results go to the audit log. The CLI can skip this check with `--no-validate-job`.
* **Management services:** Identify adds TCP connect checks on management ports. FTP and Telnet may supply server-first banners, capped at 512 bytes and two seconds. Discovery keeps its existing default port list.
* **TLS inspection:** Open ports 443, 631, and 8443 get handshake-only checks with certificate verification disabled. No application data or credentials are sent. Certificate name equality indicates self-issuance. A separate handshake checks TLS 1.0/1.1 when local OpenSSL supports it.
* **Unknown device + auto format = refuse.** The operator must choose a format explicitly.
* **ESC/POS allowlist:** init, align, bold, size, feed, QR (`GS ( k` functions 65/67/69/80/81 only), raster image, paper cut. Text segments are stripped of control bytes. Not emitted: `ESC p`, `DLE DC4`, buzzer, NV writes, panel lock.
* **Volume:** one copy per job, never sets a copy count, ≤3 jobs per run, 1 per target per 10 minutes, one target per `demo`.
* **Audit:** every attempt (allowed or refused) is written as JSONL to the state directory.

## Verification semantics

`baseline` saves TCP reachability and per-port allow or deny expectations for its vantage point. `verify` reports PASS, EXPOSED, OVER-BLOCKED, or INCONCLUSIVE against that policy. A silent denied port needs same-target liveness evidence from an open or refused connection during verification, an allowed-network snapshot at most 30 minutes old, or a weaker operator assertion.

## Print status

Raw printing reports socket submission only. Plain IPP can report acceptance with a job ID and polls Get-Job-Attributes for completion or failure for up to about 90 seconds. The audit log records the final stage. The GUI runs submission and tracking in its background worker.

IPPS on port 631 is assessed through a TLS handshake. Print submission over IPPS remains unsupported.
