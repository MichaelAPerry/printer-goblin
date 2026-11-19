---
layout: default
title: "You've been gobbed! Now what?"
---

<!-- Draft by local wording model (qwen3.5:9b); fact-checked and corrected. -->

<p align="center"><img src="goblin.png" width="180" alt="Printer Goblin mascot"></p>

[What each finding means and how to fix it](findings/) · [About this project](about)

# You've been gobbed! Now what?

Congratulations on discovering **Printer Goblin**, our open-source tool designed to help organizations audit their printing infrastructure. If you found this page after scanning a QR code on a **"YOU'VE BEEN GOBBED!"** printout, take a breath. Printer Goblin only works on private networks, and its operator has to type the printer's address to confirm before anything prints. It is built to check whether printers are properly fenced off, and it cannot change printer settings or read stored documents. This page explains what the tool does and doesn't do. Whether a particular printout came from a planned test is something your IT team can confirm.

Here is everything you need to know, depending on your role.

## Found this page on a printout?

A Printer Goblin notice normally means someone ran a check and the printer could be reached from a network that shouldn't reach it. The tool is designed to print one page and read basic printer details. It does not change printer settings, read stored documents, or send cash-drawer or other peripheral commands. The page itself contains no information about you.

**Hand the sheet to your IT or Security team**, whether or not you were told a test was happening. The printed details (the printer's address, the time, and the source network) help them confirm whether the check was expected and find the gap in the network. Once they've dealt with it, the sheet can be discarded.

## What the test showed (for IT)

For our Information Technology administrators, here is a technical breakdown of what "being gobbed" implies. The fact that a host on one network segment successfully opened a connection to the printer indicates specific vulnerabilities in your segmentation or hardening.

Typically, printers accept incoming jobs on standard ports such as **TCP 9100** (raw/AppSocket/JetDirect), **TCP 631** (IPP/IPPS), and **TCP 515** (LPD). They frequently expose management web interfaces on **HTTP 80/443** and allow monitoring via **SNMP on UDP 161**. The ability to connect to these ports from an unauthorized segment highlights gaps in your firewall rules or VLAN design.

### Why this matters
Printers are often legacy devices that are patched less frequently than servers or workstations. Beyond simple data leakage, many models store or cache print jobs, which can expose sensitive documents. Many administrative web UIs ship with default credentials that are rarely changed. Furthermore, a compromised printer can serve as a foothold for lateral movement within the network.

This is particularly critical for Point-of-Sale (POS) environments. Receipt and ESC-POS printers on POS networks often share a network segment with payment terminals. Anything that can reach the cardholder data environment can be pulled into PCI DSS scope, and a poorly isolated printer is a possible path toward payment systems.

## Fix it

To remediate these findings and secure your infrastructure against similar scans, follow this checklist:

1.  **Segment Your Network**: Place all printers in a dedicated VLAN or subnet. Configure firewalls so that only authorized print servers (or specific trusted client subnets) can reach the job submission ports (9100, 631, 515). Explicitly deny access from guest networks, IoT devices, and other untrusted segments. Restrict management traffic (HTTP/HTTPS on 80/443, SNMP on UDP 161) strictly to an administrative network with strong authentication.

2.  **Use a Print Server**: Ideally, clients should never talk directly to the hardware printer. Deploy a print server, such as CUPS (Common Unix Printing System) or a Windows Print Server. Configure clients to submit jobs only to the print server; then, configure the firewall so only the print server initiates connections to the printers. This adds a necessary layer of abstraction and security control.

3.  **Hardening Protocols**: Disable protocols you do not actively use on the printer firmware. Turn off legacy support for LPD, raw TCP 9100, FTP, Telnet, and SNMPv1/v2c (especially those using the default "public" community string). If you require monitoring, prefer **SNMPv3** with authenticated encryption. Enable **IPPS (IPP over TLS)** wherever supported to encrypt job data in transit.

4.  **Credential Management and Firmware**: Change all default administrator passwords immediately. Ensure the printer firmware is updated to the latest stable version available from the manufacturer. Disable unneeded features such as Wi-Fi Direct or cloud print services that increase the attack surface.

5.  **POS Specifics**: For receipt and ESC-POS printers specifically, ensure they are reachable only from the designated POS segment. They must never be accessible from guest Wi-Fi networks or general corporate user networks and to keep your PCI DSS scope small.

6.  **Guest Wi-Fi Safety**: If you have a guest network, ensure client isolation is enabled to prevent guests from scanning local subnets. Additionally, block traffic from the guest network to private (RFC 1918) destinations so guests cannot reach internal printers or servers.

## Prove the fix worked

1. From the network segment you want to test, record a baseline before applying the fix. All selected ports are expected to be blocked by default. Add `--allow 631` if IPP should stay reachable from that segment.

    ```bash
    printer-goblin baseline <printer-ip> --out before.json
    ```

2. After applying the fix, take a reference snapshot from a network that can still reach the printer. The snapshot must show an open port for each printer and be at most 30 minutes old.

    ```bash
    printer-goblin snapshot <printer-ip> --out ref.json
    ```

3. Back on the baseline network, run verification. In the GUI, choose the snapshot file in the Verify section.

    ```bash
    printer-goblin verify before.json --reference ref.json
    ```

- **PASS (0)** means the selected ports match the policy.
- **EXPOSED (3)** means a port that should be blocked is open.
- **OVER-BLOCKED (5)** means a port that should stay reachable is unavailable.
- **INCONCLUSIVE (4)** means a silent printer may be offline. Take a fresh reference snapshot or use `--printer-online` if you can confirm it is online. The report marks this assertion as weaker evidence than a network response.

Results apply only from the network where you ran verification. Repeat for each segment you need to test.

## About Printer Goblin

Finally, a brief note on the tool itself. **Printer Goblin** is an open-source project intended strictly for authorized security testing and network hygiene audits. It operates with several safety guards in place:
*   It refuses public IP addresses outright; it only works on private and link-local networks.
*   It requires the operator to type the target address manually to confirm intent, so nothing prints by accident.
*   To avoid disruption during testing, it prints at most one notice per printer every 10 minutes.
*   Crucially, it never sends commands that would open cash drawers, sound buzzers, write to printer memory, or control other peripherals.

By engaging with this tool and reading this guide, you are taking a proactive step toward a more secure office environment. Thank you for your cooperation!