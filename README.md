# Printer Goblin

<p align="center"><img src="assets/goblin-source.png" width="220" alt="Printer Goblin Mascot"></p>

**Printer Goblin** shows whether your printers can be reached from networks that absolutely shouldn't reach them. It does this by printing a friendly "YOU'VE BEEN GOBBED!" notice on the printer itself.

It's not an attack tool. It's an audit tool. Think of it as a friendly goblin popping out to check if your network segmentation is actually working. Printers are often forgotten when designing flat networks. If your guest Wi-Fi, IoT devices, or user workstations can reach a printer's ports, you have a segmentation gap. This matters especially for receipt printers on point-of-sale networks, where PCI DSS scoping rules apply.

## What It Does

The tool works in a strict, five-step sequence to keep things safe and clear:

1.  **Discover**: It finds open printer ports (raw port 9100, IPP on 631, LPD on 515, or web interfaces on 80/443) within a private network range you choose.
2.  **Identify**: It asks the printer what it is using via IPP, SNMP, and its web page—without printing anything yet.
3.  **Preview**: Before committing to ink, it shows you exactly what the printout will look like.
4.  **Print**: If authorized, it prints one notice featuring the mascot, a short friendly message, and a "What the goblin saw" fact sheet listing the model, firmware, open ports, and findings like "Raw print port 9100 reachable." This also includes a QR code linking to a remediation guide.
5.  **Verify**: You save a "before" snapshot of what is reachable, fix your network, then check again from the same place. Each port in the baseline has an expectation: `deny` (the default, which should become unreachable) or `allow` (for example, IPP that the print server's network is meant to reach, set with `--allow 631`). A PASS means every denied port is now unreachable and every allowed port still answers. EXPOSED means a denied port is still reachable, and OVER-BLOCKED means an allowed port stopped answering. INCONCLUSIVE means the printer may simply have been off, so there was no proof the silence came from the network.

## Who Is This For?

Whether you manage enterprise servers, run a small coffee shop with thermal printers, or teach cybersecurity students about segmentation flaws, this tool adapts to you.

*   **IT Admins**: Check your POS networks for PCI gaps quickly.
*   **Small Business Owners**: Ensure guest Wi-Fi can't print customer receipts without permission.
*   **Security Teachers**: Have students discover vulnerable devices and prove their findings with physical evidence (paper).

It works seamlessly with office printers using PDF, PostScript, PCL, or PWG Raster over IPP, as well as thermal receipt printers using ESC/POS commands on 58mm and 80mm paper rolls.

## Getting Started

### Download

Get the standalone executable for Windows, macOS, or Linux from [GitHub Releases](https://github.com/MichaelAPerry/printer-goblin/releases). On macOS and Linux, make the downloaded file executable with `chmod +x <filename>`. Run it without arguments to open the local web GUI. The release notes explain how to verify each download against `SHA256SUMS.txt`.

### Install from source

To get up and running, you'll need Python 3.10 or newer. The only external dependency is the `segno` library for generating QR codes.

Clone the repo, set up a virtual environment, and install:

```bash
git clone https://github.com/MichaelAPerry/printer-goblin.git
cd printer-goblin
python -m venv .venv
# Activate the environment
# macOS/Linux:
. .venv/bin/activate
# Windows:
# .venv\Scripts\activate

pip install -e .
```

Once installed, simply run `printer-goblin` with no arguments to open the GUI in your web browser. It runs entirely on your own computer (`127.0.0.1`) and is protected by a one-time session token.

For those who prefer scripting or need to automate checks, the command line offers full control:

```bash
printer-goblin discover 192.168.50.0/24
printer-goblin identify 192.168.50.23
printer-goblin preview --format pdf -o notice.pdf
printer-goblin preview --format pwg --media a4 -o notice.pwg
printer-goblin baseline 192.168.50.23 --out before.json
printer-goblin demo 192.168.50.23 --yes-i-am-authorized
printer-goblin verify before.json
```

## Assessment report

Run `printer-goblin report 192.168.50.23 --baseline before.json` or select **Download report** after **Identify** in the GUI. The report runs a fresh, paper-free assessment and saves a self-contained HTML file with findings, remediation links, serial-masked evidence, and matching local audit events. Omit `--baseline` to skip isolation verification. Use `--format md` for tickets, `--format json` for structured data, or `--no-validate-job` to skip the IPP authorization check.

## Assess a whole fleet

`printer-goblin assess 192.168.50.0/24` discovers printers in the range (same private-only scope and range limits as `discover`), runs the paper-free assessment on each (at most four at a time), and writes one consolidated report: device table, how common each finding is, and ranked configuration recommendations such as "Turn off Telnet on 3 of 20 printers". Nothing is printed on any device. Choose `--format html|md|json|csv`, `--out PATH`, `--ports`, or `--no-validate-job`. In the GUI, use **Assess all (no printing)** after **Discover**, then download the report.

### Large ranges

Scans will discover and assess private IP ranges up to /16 (65,536 addresses). For any range exceeding /22 (1,024 addresses), the tool displays an estimated duration alongside a warning before execution, requiring confirmation in interactive sessions. This estimate represents a worst-case scenario assuming timeouts for every address; scanning a /24 with the default five ports takes roughly 16 seconds, while a /16 requires approximately 68 minutes. For broader private networks like the entire 10.0.0.0/8 block, scan them incrementally in /16 segments.

### Pages of code instead of the notice?

This occurs when a printer receives a language it doesn't support and prints it as raw text. Raw (port 9100) PostScript and PCL jobs are now wrapped in a PJL header that specifies the job's language. It contains only job start, language switch, and job end commands, and never alters device settings. PDF and PWG Raster are sent exclusively over IPP. Older devices, such as HP LaserJets with JetDirect cards, are now identified via the languages they list over SNMP. If text still appears instead of the notice, choose the PCL format.

## Try it without a printer

Printer Goblin ships a fake printer for demos and tests. It listens on loopback only, and the normal safety checks still apply (typed confirmation, `--yes-i-am-authorized`, cooldown, audit log).

```bash
printer-goblin --fake-printer office-open identify
printer-goblin --fake-printer office-open demo --yes-i-am-authorized
printer-goblin --fake-printer office-open baseline --out demo.json   # then verify in the same way
printer-goblin fake-printer --profile receipt                        # run it in the foreground and watch traffic
```

Profiles: `office-open` (IPP Everywhere, SNMP, 9100/515/80), `office-locked` (IPP only, refuses jobs with "not authorized"), `office-legacy` (an older JetDirect-style laser: no readable IPP, languages listed over SNMP, raw 9100), and `receipt` (Epson TM-style, SNMP and 9100 only). Demo mode is a CLI flag only; the GUI can be started with it (`printer-goblin --fake-printer office-open gui`) and pointed at `127.0.0.1`.

## Built to be Polite

Printer Goblin is designed to prove a point without causing trouble:

*   **Network Scope**: It only scans private and link-local networks. Public IP addresses are refused automatically.
*   **Scan Limits**: Scans stay inside private ranges, up to a /16. Anything over a /22 shows an estimated time and a warning first.
*   **Authorization Required**: You must explicitly flag that you are authorized AND type the printer's address to trigger a print job.
*   **Rate Limiting**: At most one notice per printer every 10 minutes, capped at three notices per run.
*   **No Side Effects**: It never sends cash-drawer commands, buzzer triggers, or printer-memory control codes.
*   **Safe Identification**: The identify phase never sends raw data to the print port; it only asks questions over IPP, SNMP and HTTP.
*   **Audit Trail**: Every attempt is written to a local audit log on your machine.

> **⚠️ Warning**: Only use this tool on networks and printers you own or have written permission to test. Testing without permission may be illegal.

## Resources & License

If you see a QR code on a printed notice, scan it for the full **[remediation guide](https://michaelaperry.github.io/printer-goblin/)**.

For more context, check out the **[about page](https://michaelaperry.github.io/printer-goblin/about)**. If you are interested in how the pieces fit together, the technical design is documented in [ARCHITECTURE.md](ARCHITECTURE.md). To run the tests: `pip install -e ".[dev]" && pytest -q`.

This project is released under the MIT License. Go forth and goblin responsibly.
