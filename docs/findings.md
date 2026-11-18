---
layout: default
title: What the goblin found, and how to fix it
permalink: /findings/
---

<!-- Draft by local wording model (qwen3.5:9b); fact-checked and corrected. -->

<p align="center"><img src="../goblin.png" width="140" alt="Printer Goblin mascot"></p>

[Back to the guide](../) · [About this project](../about)

# What the goblin found, and how to fix it

Each section below matches one finding on a Printer Goblin fact sheet or report. The QR code on a printed notice jumps straight to the most serious one. Every fix comes down to the same idea: turn off what you don't use, and make sure only the networks that should print can reach the printer.

Menu names differ by vendor, so these steps describe settings in general terms. Check your printer's admin guide for the exact path.

## Printer approved a print job without login {#unauth-print}

**What it means:** The goblin asked the printer whether it would accept a job (an IPP "Validate-Job" check, which prints nothing), and the printer said yes without asking for a login.

**Why it matters:** Validate-Job is a dry run, so it doesn't prove a real job would print: a few printers ask for credentials only when a job is actually submitted. Usually, though, a printer that approves the check will also print, and anyone who can reach it from this network could send spam, fake notices, or simply waste paper and toner. Printer Goblin's one-page demo confirms it for certain.

**How to fix:**
- Restrict network access so only your print server or the networks that should print can reach the printer.
- If the printer supports it, require authentication for IPP printing in its web admin.
- If no one uses IPP/AirPrint printing on this printer, turn it off.

## Raw print port 9100 open {#raw-9100}

**What it means:** Port 9100 (also called AppSocket or JetDirect) accepts raw print data. It has no login.

**Why it matters:** Anyone who can reach the port can print anything. On many office printers the same port also accepts printer-control languages such as PJL, which can read or change some settings.

**How to fix:**
- Turn off raw/port 9100 printing in the printer's web admin if you don't need it.
- Otherwise, use a firewall or VLAN rule so only your print server can reach port 9100.
- Prefer printing through a print server or authenticated IPP.

## IPP printing allows anonymous jobs {#ipp-no-auth}

**What it means:** The printer advertises that its IPP print addresses need no authentication.

**Why it matters:** Anyone who can reach the printer can send it print jobs.

**How to fix:**
- Require authentication for IPP printing in the printer's web admin, if it's supported.
- Restrict network access so only trusted networks or a print server can reach the printer.

## IPP printing requires authorization {#ipp-auth-required}

**What it means:** Good news: the printer refused the goblin's print check because no credentials were supplied.

**Why it matters:** This setting stops casual printing from networks that shouldn't print.

**What to keep doing:**
- Leave IPP authentication turned on.
- Still limit which networks can reach the printer. Authentication and segmentation work best together.

## IPP answers without TLS {#ipp-plain}

**What it means:** The printer answered IPP requests on port 631 over plain HTTP without a login, so its details were readable.

**Why it matters:** Print jobs sent this way cross the network unencrypted, and anyone on the network can read the printer's details.

**How to fix:**
- Turn on IPPS (IPP over TLS) if the printer supports it, and have clients use it.
- Restrict port 631 with a firewall or VLAN so only trusted networks can reach it.
- Update firmware. Newer versions often add or improve TLS support.

## LPD port 515 open {#lpd}

**What it means:** The printer accepts jobs over LPD, an old print protocol on port 515 that has no authentication.

**Why it matters:** Anyone who can reach the port can print, and almost nothing modern needs LPD.

**How to fix:**
- Turn off LPD/LPR printing in the printer's web admin.
- If something still depends on it, block port 515 from everywhere except that system.

## SNMP answers community 'public' {#snmp-public}

**What it means:** The printer answered SNMP requests that used the default community name "public", which works like a well-known password.

**Why it matters:** Anyone on the network can read details such as the model, firmware and network settings, which helps an attacker plan.

**How to fix:**
- If nothing monitors the printer over SNMP, turn SNMPv1/v2c off.
- If monitoring is needed, switch to SNMPv3 with authentication, or at least change the community name.
- Restrict SNMP (UDP 161) to your monitoring server.

## Web admin served over HTTP {#http-admin}

**What it means:** The printer's admin web page is available without encryption on port 80.

**Why it matters:** Admin passwords and settings typed into that page cross the network in plain text.

**How to fix:**
- Turn on HTTPS for the web admin, and turn HTTP off or redirect it to HTTPS.
- Restrict the admin page to IT workstations or a management network.
- Make sure the default admin password has been changed.

## Web admin on HTTPS {#https-admin}

**What it means:** The admin web page is offered over HTTPS, which is good. This finding is a reminder to check what's behind it.

**Why it matters:** Encryption doesn't help if the admin password is still the factory default. Anyone who guesses it can change the printer's settings.

**How to fix:**
- Change the default administrator password.
- Restrict the admin page to IT workstations or a management network.

## Telnet port open {#telnet}

**What it means:** Telnet, an unencrypted remote console, is listening on port 23.

**Why it matters:** Anything typed into it, including passwords, crosses the network in plain text.

**How to fix:**
- Turn Telnet off in the printer's web admin. Almost no one needs it.
- If remote console access is needed, use SSH or HTTPS instead, limited to admin workstations.

## FTP port open {#ftp}

**What it means:** FTP is listening on port 21. On printers it is usually there to accept print files, and sometimes firmware uploads.

**Why it matters:** FTP is unencrypted. Depending on the model, anyone who can connect may be able to print or upload files, and any password crosses the network in plain text.

**How to fix:**
- Turn FTP printing off in the printer's web admin if you don't use it.
- Otherwise, block port 21 from everywhere except the systems that need it.

## SSH port open {#ssh}

**What it means:** SSH is listening on port 22. This is informational. SSH is encrypted, but it is still a way in.

**Why it matters:** An admin service that no one uses is something you'll forget to patch or protect.

**How to fix:**
- Turn it off if no one manages the printer over SSH.
- Otherwise, limit it to admin workstations and use a strong password.

## SMB port open {#smb}

**What it means:** The printer offers SMB (Windows file sharing) on port 445, usually for scan-to-folder or file sharing.

**Why it matters:** File sharing on a printer is one more service to secure, and scanned documents can contain sensitive information.

**How to fix:**
- Turn off SMB features you don't use.
- Restrict port 445 to the file servers or workstations that need it.
- Require authentication for any shared folders.

## WSD port open {#wsd}

**What it means:** Web Services for Devices (WSD) is listening on port 5357. Windows uses it to discover printers and print to them. This is informational.

**Why it matters:** WSD advertises the printer and accepts jobs on the local network. That's usually fine on a trusted network, but unnecessary elsewhere.

**How to fix:**
- Turn WSD off if your computers print another way (IPP, a print server, or a driver port).
- Make sure network rules keep WSD traffic inside trusted networks.

## Alternate HTTP port open {#alt-http}

**What it means:** A second unencrypted web service is listening on port 8080.

**Why it matters:** It may be an extra admin or status page, and anything typed into it crosses the network in plain text.

**How to fix:**
- Find out what the service is. If it isn't needed, turn it off.
- Otherwise, restrict it to admin workstations and prefer an HTTPS equivalent.

## Alternate HTTPS port open {#alt-https}

**What it means:** A second encrypted web service is listening on port 8443. This is informational.

**Why it matters:** Every extra management service is something to protect and keep updated.

**How to fix:**
- Confirm what the service is and whether it's needed.
- Restrict it to admin workstations, and make sure its password isn't a default.

## Printer accepts TLS 1.0/1.1 {#legacy-tls}

**What it means:** The printer completed an encrypted connection using TLS 1.0 or 1.1, which are retired versions. If the report also says no TLS 1.2+ handshake succeeded, the printer may support nothing newer.

**Why it matters:** Old TLS versions have known weaknesses, and modern browsers and clients refuse them.

**How to fix:**
- In the printer's web admin, set the minimum TLS version to 1.2 if that option exists.
- Update the firmware. Newer versions often add TLS 1.2 support.
- If the printer can't do TLS 1.2, restrict its admin and print services to a protected network, and plan to replace it.

## Firmware reported {#firmware}

**What it means:** The printer reported its firmware version. This is informational. Printer Goblin does not check whether that version is current or vulnerable.

**Why it matters:** Printer firmware gets security fixes like any other software, but printers are often never updated.

**How to fix:**
- Compare the version with the vendor's security advisories (the report links them for common brands).
- Install updates using the vendor's official tool or the printer's web admin.

## Still stuck?

Share the printed sheet (or the report) and this page with your IT or security team. The sheet shows which network the test came from, which is the most useful clue for fixing segmentation. To check your work afterwards, see [Prove the fix worked](../#prove-the-fix-worked).
