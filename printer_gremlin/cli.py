"""Printer Gremlin command-line interface."""

from __future__ import annotations

import argparse
import http.client
import json
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Optional

from . import discovery, net, safety, scope, transports, verify
from .identify import Fingerprint, identify
from .payloads import pcl, pdf, postscript, receipt
from .payloads.notice import DEFAULT_GUIDE_URL, build_notice

_RENDERERS = {"ps": postscript.render, "pcl": pcl.render, "pdf": pdf.render,
              "escpos": receipt.render}
_MIME = {"ps": "application/postscript", "pcl": "application/vnd.hp-pcl",
         "pdf": "application/pdf", "escpos": "application/octet-stream"}
_EXTENSIONS = {"ps": "ps", "pcl": "pcl", "pdf": "pdf", "escpos": "bin"}


def _port(value: str) -> int:
    try:
        port = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("port must be an integer") from exc
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError("port must be in 1..65535")
    return port


def _ports(value: str) -> list[int]:
    return [_port(token) for token in value.split(",")]


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="printer-gremlin")
    sub = parser.add_subparsers(dest="command", required=True)

    discover = sub.add_parser("discover", help="find open printer ports within scope")
    discover.add_argument("cidr")
    discover.add_argument("--ports", nargs="+", type=_ports)
    discover.add_argument("--json", action="store_true")

    fingerprint = sub.add_parser("identify", help="query a printer without printing")
    fingerprint.add_argument("target")
    fingerprint.add_argument("--json", action="store_true")

    preview = sub.add_parser("preview", help="render a notice to a local file")
    preview.add_argument("--format", choices=_RENDERERS, required=True)
    preview.add_argument("-o", "--output", type=Path)
    preview.add_argument("--target", default="10.0.0.5")
    preview.add_argument("--port", type=_port, default=9100)

    demo = sub.add_parser("demo", help="print one authorized notice")
    demo.add_argument("target")
    demo.add_argument("--via", choices=("raw", "ipp"))
    demo.add_argument("--format", choices=("auto", *_RENDERERS), default="auto")
    demo.add_argument("--port", type=_port)
    demo.add_argument("--guide-url", default=DEFAULT_GUIDE_URL)
    demo.add_argument("--note", default="")
    demo.add_argument("--yes-i-am-authorized", action="store_true")

    baseline = sub.add_parser("baseline", help="save current TCP reachability")
    baseline.add_argument("targets", nargs="+")
    baseline.add_argument("--out", required=True, type=Path)
    baseline.add_argument("--label", default="")
    baseline.add_argument("--ports", nargs="+", type=_ports)

    verification = sub.add_parser("verify", help="check TCP reachability against a baseline")
    verification.add_argument("baseline_file", type=Path)
    return parser


def _select_job(fingerprint: Fingerprint, format_name: str,
                via: Optional[str]) -> tuple[str, str]:
    if format_name != "auto":
        return format_name, via or "raw"
    if fingerprint.kind == "unknown":
        raise safety.PrintRefused(
            "Unknown printer. Pass --format explicitly. Raw bytes sent to an unknown "
            "device may print garbage pages."
        )
    if fingerprint.kind == "thermal-escpos":
        return "escpos", via or "raw"
    if via != "raw" and "pdf" in fingerprint.languages and 631 in fingerprint.ports:
        return "pdf", "ipp"
    if "postscript" in fingerprint.languages:
        return "ps", via or "raw"
    return "pcl", via or "raw"


def _demo(args: argparse.Namespace) -> int:
    governor = safety.PrintGovernor()
    audit = {"target": args.target}
    governor.audit("attempt", **audit)
    try:
        target = str(scope.resolve_target(args.target))
        audit["ip"] = target
        if not args.yes_i_am_authorized:
            raise safety.PrintRefused("Printing requires --yes-i-am-authorized.")
        fingerprint = identify(target)
        format_name, protocol = _select_job(fingerprint, args.format, args.via)
        port = args.port if args.port is not None else (631 if protocol == "ipp" else 9100)
        notice = build_notice(target, port, protocol, net.source_ip(target),
                              args.guide_url, args.note)
        data = _RENDERERS[format_name](notice)
        audit.update(port=port, protocol=protocol, format=format_name, bytes=len(data))
        summary = (
            f"[gremlin] {target}:{port} via {protocol.upper()} | {format_name} | {len(data)} bytes\n"
            f"One notice: {notice.headline}\n"
            + "\n".join(notice.lines)
            + f"\nQR and guide URL: {notice.url}\n"
            + "\n".join(notice.footer)
        )
        # Escape terminal control characters in operator-supplied notice fields.
        summary = "".join(char if char.isprintable() or char == "\n" else "?" for char in summary)
        governor.check(target, len(data))  # fail fast before asking the operator
        if not safety.confirm(target, summary):
            raise safety.PrintRefused("Address confirmation declined.")
        governor.check(target, len(data))
        try:
            if protocol == "ipp":
                path = fingerprint.ipp_path if port == 631 else None
                status, job_id = transports.send_ipp(
                    target, data, _MIME[format_name], port, path or "/ipp/print"
                )
                audit.update(ipp_status=status, job_id=job_id)
                if status >= 0x0100:
                    raise OSError(f"Print-Job failed with IPP status 0x{status:04x}")
            else:
                transports.send_raw(target, data, port)
        finally:
            # A transport error can occur after the printer has received the job.
            governor.record(target)
    except (safety.PrintRefused, scope.ScopeError, EOFError, KeyboardInterrupt) as exc:
        governor.audit("refused", **audit, reason=str(exc) or "confirmation interrupted")
        raise
    except Exception as exc:
        governor.audit("failed", **audit, reason=str(exc))
        raise
    governor.audit("sent", **audit)
    print("[gremlin] One notice submitted.")
    return 0


def _selected_ports(args: argparse.Namespace) -> tuple[int, ...]:
    if args.ports is None:
        return discovery.DEFAULT_PORTS
    return tuple(port for group in args.ports for port in group)


def _json(value: object) -> str:
    return json.dumps(value, indent=2, default=lambda raw: raw.hex() if isinstance(raw, bytes) else str(raw))


def main(argv: Optional[list[str]] = None) -> int:
    """Run one CLI command and return its exit status."""
    try:
        args = _parser().parse_args(argv)
    except SystemExit as exc:
        return int(exc.code)

    try:
        if args.command == "discover":
            hosts = discovery.discover(args.cidr, _selected_ports(args))
            if args.json:
                print(_json([asdict(host) for host in hosts]))
            elif hosts:
                for host in hosts:
                    print(f"{host.ip}  open: {', '.join(map(str, host.open_ports))}")
            else:
                print("[gremlin] No open ports found.")
        elif args.command == "identify":
            result = identify(args.target)
            if args.json:
                print(_json(asdict(result)))
            else:
                print(f"[gremlin] {result.ip}: {result.kind}")
                print(f"Open ports: {', '.join(map(str, result.ports)) or 'none'}")
                print(f"Languages: {', '.join(result.languages) or 'unknown'}")
                if result.http_title:
                    print(f"HTTP title: {result.http_title!r}")
                for reason in result.reasons:
                    print(f"- {reason!r}")
        elif args.command == "preview":
            notice = build_notice(args.target, args.port, "preview", "preview")
            output = args.output
            if output is None:
                output = Path(f"printer-gremlin-notice.{_EXTENSIONS[args.format]}")
            output.write_bytes(_RENDERERS[args.format](notice))
            print(f"[gremlin] Notice saved to {output}.")
        elif args.command == "demo":
            return _demo(args)
        elif args.command == "baseline":
            verify.baseline(args.targets, _selected_ports(args), args.out, args.label)
            print(f"[gremlin] Baseline saved to {args.out}.")
        elif args.command == "verify":
            report = verify.compare(args.baseline_file)
            print(_json(report))
            return 0 if report["verdict"] == "PASS" else 3
    except (OSError, ValueError, safety.PrintRefused, http.client.HTTPException,
            EOFError, KeyboardInterrupt) as exc:
        print(f"[gremlin] {exc or 'Interrupted.'}", file=sys.stderr)
        return 1
    return 0
