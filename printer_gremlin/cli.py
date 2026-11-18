"""Printer Gremlin command-line interface."""

from __future__ import annotations

import argparse
import http.client
import json
import sys
from pathlib import Path
from typing import Optional

from . import discovery, safety, workflow
from .verify import EXIT_CODES
from .identify import Fingerprint, identify
from .payloads.notice import DEFAULT_GUIDE_URL, build_notice


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
    preview.add_argument("--format", choices=workflow.FORMATS, required=True)
    preview.add_argument("-o", "--output", type=Path)
    preview.add_argument("--target", default="10.0.0.5")
    preview.add_argument("--port", type=_port, default=9100)

    demo = sub.add_parser("demo", help="print one authorized notice")
    demo.add_argument("target")
    demo.add_argument("--via", choices=("raw", "ipp"))
    demo.add_argument("--format", choices=("auto", *workflow.FORMATS), default="auto")
    demo.add_argument("--port", type=_port)
    demo.add_argument("--guide-url", default=DEFAULT_GUIDE_URL)
    demo.add_argument("--note", default="")
    demo.add_argument("--yes-i-am-authorized", action="store_true")

    for command in (preview, demo):
        command.add_argument("--paper", choices=("58", "80"), default="80")
        command.add_argument("--raster-qr", action="store_true")
    preview.add_argument("--media", choices=("letter", "a4"), default="letter")
    preview.add_argument("--sample", action="store_true")

    gui = sub.add_parser("gui", help="open the local Printer Gremlin interface")
    gui.add_argument("--port", type=int, default=0)
    gui.add_argument("--no-browser", action="store_true")

    baseline = sub.add_parser("baseline", help="save current TCP reachability")
    snapshot = sub.add_parser("snapshot", help="save a liveness reference from an allowed network")
    for command in (baseline, snapshot):
        command.add_argument("targets", nargs="+")
        command.add_argument("--out", required=True, type=Path)
        command.add_argument("--label", default="")
        command.add_argument("--ports", nargs="+", type=_ports)
    baseline.add_argument("--expect", choices=("deny",), default="deny",
                          help="default expectation for selected ports")
    baseline.add_argument("--allow", action="append", type=_ports, default=[],
                          help="port(s) expected to stay reachable")

    verification = sub.add_parser("verify", help="check TCP reachability against a baseline")
    verification.add_argument("baseline_file", type=Path)
    verification.add_argument("--reference", type=Path)
    verification.add_argument("--printer-online", action="store_true")
    verification.add_argument("--json", action="store_true")
    return parser


def _selected_ports(args: argparse.Namespace) -> tuple[int, ...]:
    if args.ports is None:
        return discovery.DEFAULT_PORTS
    return tuple(port for group in args.ports for port in group)


def _print_verify(report: dict) -> None:
    print(f"[gremlin] Verify: {report.get('label', '')}")
    for ip, ports in report["results"].items():
        for port, row in ports.items():
            print(f"  {ip}:{port:<5} {row['policy']:>5} {row['before']:>8} -> "
                  f"{row['after']:<8} {row['classification']}")
        evidence = ", ".join(report["liveness"][ip]) or "none"
        print(f"  Liveness for {ip}: {evidence}")
    if report["vantage"]["behind_wsl_nat"]:
        print("  note: probed from inside WSL; the network sees this PC's Windows address.")
    print(f"[gremlin] {report['verdict']} - {report['explanation']}")
    print(f"  {report['note']}")
    if report["liveness_note"]:
        print(f"  {report['liveness_note']}")


def _json(value: object) -> str:
    return json.dumps(value, indent=2, default=lambda raw: raw.hex() if isinstance(raw, bytes) else str(raw))


def main(argv: Optional[list[str]] = None) -> int:
    """Run one CLI command and return its exit status."""
    if argv is None:
        argv = sys.argv[1:]
    if not argv:
        argv = ["gui"]  # no arguments: open the friendly GUI
    try:
        args = _parser().parse_args(argv)
    except SystemExit as exc:
        return int(exc.code)

    try:
        if args.command == "discover":
            hosts = workflow.discover(args.cidr, _selected_ports(args))["hosts"]
            if args.json:
                print(_json(hosts))
            elif hosts:
                for host in hosts:
                    ports = ", ".join(map(str, host["open_ports"]))
                    print(f"{host['ip']}  open: {ports}")
            else:
                print("[gremlin] No open ports found.")
        elif args.command == "identify":
            result = workflow.identify(args.target, probe=identify)
            if args.json:
                print(_json(result))
            else:
                print(f"[gremlin] {result['ip']}: {result['kind']}")
                print(f"Open ports: {', '.join(map(str, result['ports'])) or 'none'}")
                print(f"Languages: {', '.join(result['languages']) or 'unknown'}")
                if result['http_title']:
                    print(f"HTTP title: {result['http_title']!r}")
                for reason in result['reasons']:
                    print(f"- {reason!r}")
        elif args.command == "preview":
            example = None
            if args.sample:
                example = Fingerprint(args.target, ports=[9100, 631], kind="office", ipp_ok=True,
                                      ipp_attrs={"printer-make-and-model": ["Example Office Printer"]},
                                      firmware="1.0")
            notice = build_notice(args.target, args.port, "preview", "preview", fingerprint=example)
            if args.sample:
                notice.device.insert(0, "(sample identification data)")
            output = args.output
            if output is None:
                output = Path(f"printer-gremlin-notice.{workflow.EXTENSIONS[args.format]}")
            output.write_bytes(workflow.render_notice(
                notice, args.format, args.paper, not args.raster_qr, media=args.media
            ))
            print(f"[gremlin] Notice saved to {output}.")
        elif args.command == "demo":
            reported = []

            def show_stage(report):
                message = workflow.print_status_text(report)
                print(f"[gremlin] {message}", flush=True)
                reported.append(message)

            try:
                result = workflow.run_demo(args, identify=identify, on_status=show_stage)
                if workflow.print_status_text(result) not in reported:
                    show_stage(result)
                return 1 if result["status"] == "failed" else 0
            finally:
                print(workflow.PHYSICAL_PRINT_NOTE, flush=True)
        elif args.command == "gui":
            from .gui.server import serve
            serve(args.port, open_browser=not args.no_browser)
        elif args.command == "baseline":
            allowed = [port for group in args.allow for port in group]
            ports = _selected_ports(args)
            if args.ports is None:
                ports = (*ports, *allowed)
            workflow.baseline(args.targets, ports, args.out, args.label, expect=args.expect, allow=allowed)
            print(f"[gremlin] Baseline saved to {args.out}.")
        elif args.command == "snapshot":
            workflow.snapshot(args.targets, _selected_ports(args), args.out, args.label)
            print(f"[gremlin] Reference snapshot saved to {args.out}.")
        elif args.command == "verify":
            report = workflow.verify(args.baseline_file, reference=args.reference,
                                     printer_online=args.printer_online)
            if args.json:
                print(_json(report))
            else:
                _print_verify(report)
            return EXIT_CODES[report["verdict"]]
    except (OSError, ValueError, safety.PrintRefused, http.client.HTTPException,
            EOFError, KeyboardInterrupt) as exc:
        print(f"[gremlin] {exc or 'Interrupted.'}", file=sys.stderr)
        return 1
    return 0
