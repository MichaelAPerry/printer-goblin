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
5.  **Verify**: You save a "before" snapshot of what is reachable, fix your network, then check again from the same place. A PASS result means no printer ports were reachable from that zone anymore.

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

## Built to be Polite

Printer Goblin is designed to prove a point without causing trouble:

*   **Network Scope**: It only scans private and link-local networks. Public IP addresses are refused automatically.
*   **Scan Limits**: Scans are limited to 1,024 addresses to keep scans small and quiet.
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
