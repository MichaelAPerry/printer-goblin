---
layout: default
title: About Printer Gremlin
---

<!-- Draft by local wording model (qwen3.5:9b); fact-checked and corrected. -->

# About Printer Gremlin

<p align="center"><img src="gremlin.png" width="180" alt="Printer Gremlin mascot"></p>

Printer Gremlin is a free, open-source tool designed to foster printer security awareness and test network segmentation. Built under the MIT license, it brings tangible impact to often-overlooked vulnerabilities in the printing infrastructure of small businesses, educational institutions, and larger organizations alike.

The core idea behind Printer Gremlin is simple yet effective: abstract technical findings like "port 9100 is reachable from guest Wi-Fi" are easy for administrators to skim over and ignore. A page that physically erupts from a printer tray shouting "YOU'VE BEEN GOBBED!" is much harder to miss. By turning a dangerous segmentation gap into something people can literally hold in their hands, the tool ensures security gaps cannot be ignored. Each printout includes a QR code linking directly to the fix, bridging the gap between discovery and remediation.

The mascot for this project is a friendly gremlin who magically pops out of the paper tray holding up the page it has just grabbed. This whimsical imagery underscores the playful nature of the project while delivering a serious message about security hygiene.

### Who Is This For?
Printer Gremlin is made for IT administrators and security teams. It is equally useful for small businesses that may not have dedicated security staff but still need to secure their print infrastructure. Cybersecurity educators running classroom or lab demos will find it invaluable, as the physical output sparks conversations about network topology and segmentation during training sessions.

### Safety and Ethics
Safety and ethics are central to this project. Printer Gremlin is explicitly **not** an exploitation tool, nor is it a scanner for the broader internet. The software is designed with strict safeguards: it refuses to operate against public IP addresses, ensures printing only occurs after operator confirmation, keeps total print volume to a minimum to reduce waste and noise, and never sends commands that could control peripherals like cash drawers.

We adhere to strict ethical guidelines. You should only test networks and printers you own or have written permission to evaluate. It is good practice to tell people when a test is happening where appropriate. Furthermore, the printout itself clearly states it was generated during an authorized test and politely asks anyone who finds it to pass the page along to IT.

### Get Involved
We believe in building security tools together. Issues and pull requests are welcome at https://github.com/MichaelAPerry/printer-goblin . We are particularly eager for contributions regarding reports of how Printer Gremlin behaves on specific printer models, as compatibility varies across the vast landscape of printing hardware.

For guidance on how to fix the issues discovered by the gremlin, please visit our remediation guide the [remediation guide](./).

Printer Gremlin aims to make security memorable, actionable, and undeniably real.
