"""Shared printer assessment and guarded notice submission."""

from __future__ import annotations

import http.client
import json
import time
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from threading import Lock
from typing import Optional

from . import discovery, net, safety, scope, transports, verify as verification
from .findings import Finding, findings as observed_findings
from .identify import Fingerprint, identify as fingerprint_target
from .payloads import pcl, pdf, postscript, pwg, receipt
from .protocols import ipp
from .payloads.notice import DEFAULT_GUIDE_URL, Notice, build_notice, service_lines

_RENDERERS = {"ps": postscript.render, "pcl": pcl.render, "pdf": pdf.render,
              "pwg": pwg.render, "escpos": receipt.render}
MIME_TYPES = {"ps": "application/postscript", "pcl": "application/vnd.hp-pcl",
         "pdf": "application/pdf", "pwg": "image/pwg-raster", "escpos": "application/octet-stream"}
EXTENSIONS = {"ps": "ps", "pcl": "pcl", "pdf": "pdf", "pwg": "pwg", "escpos": "bin"}

FORMATS = tuple(_RENDERERS)
_PRINT_LOCK = Lock()
_JOB_POLL_SECONDS = 90
_JOB_POLL_INTERVAL = 3
PHYSICAL_PRINT_NOTE = "Physical print not confirmed by software - check the printer."


@dataclass(frozen=True)
class PrintPlan:
    ip: str
    fingerprint: Fingerprint
    findings: list[Finding]
    protocol: str
    port: int
    format: str
    data: bytes
    summary: str
    target: str
    notice: Notice


def render_notice(notice, fmt, paper="80", native_qr=True, *, media="letter"):
    if fmt == "escpos":
        return receipt.render(notice, paper=paper, native_qr=native_qr)
    if fmt == "pwg":
        return pwg.render(notice, media=media)
    return _RENDERERS[fmt](notice)


def _select_job(fingerprint: Fingerprint, format_name: str,
                via: Optional[str]) -> tuple[str, str]:
    """Pick a format only when the printer has positively advertised it.

    Sending a language the printer doesn't speak (e.g. PCL to a host-based
    Brother laser) prints pages of garbage, so auto mode never guesses.
    """
    if format_name != "auto":
        return format_name, via or ("ipp" if format_name == "pwg" else "raw")
    if fingerprint.kind == "unknown":
        raise safety.PrintRefused(
            "Unknown printer. Pass --format explicitly. Raw bytes sent to an unknown "
            "device may print garbage pages."
        )
    if fingerprint.kind == "thermal":
        if "escpos" in fingerprint.languages:
            if via == "ipp":
                raise safety.PrintRefused("Automatic ESC/POS printing requires raw transport.")
            return "escpos", "raw"
        raise safety.PrintRefused(
            "Receipt printer detected but its command language is unconfirmed. "
            "If it supports ESC/POS (many do via an emulation setting), pass --format escpos."
        )
    langs = set(fingerprint.languages)
    ipp_ok = via != "raw" and 631 in fingerprint.ports
    if ipp_ok and "pdf" in langs:
        return "pdf", "ipp"
    if ipp_ok and "pwg-raster" in langs:
        return "pwg", "ipp"
    if "postscript" in langs:
        return "ps", via or "raw"
    if "pcl" in langs:
        return "pcl", via or "raw"
    raise safety.PrintRefused(
        "The printer did not advertise a language Printer Goblin can send "
        f"({', '.join(sorted(langs)) or 'none advertised'}). Pass --format "
        "explicitly only if you know the printer supports it."
    )


def plan_print(target, fmt="auto", via=None, port=None, guide_url=DEFAULT_GUIDE_URL,
               note="", paper="80", native_qr=True) -> PrintPlan:
    ip = str(scope.resolve_target(target))
    return _plan(target, ip, fingerprint_target, fmt, via, port, guide_url,
                 note, paper, native_qr)


def _plan(target, ip, identify, fmt, via, port, guide_url, note, paper, native_qr):
    if (fmt not in ("auto", *_RENDERERS) or via not in (None, "raw", "ipp")
            or not isinstance(paper, str) or paper not in ("58", "80")):
        raise ValueError("invalid format, protocol, or paper size")
    if port is not None and (type(port) is not int or not 1 <= port <= 65535):
        raise ValueError("port must be in 1..65535")
    if fmt == "pwg" and via == "raw":
        raise safety.PrintRefused("PWG Raster requires IPP. Select --via ipp.")
    fp = identify(ip)
    fmt, protocol = _select_job(fp, fmt, via)
    port = port if port is not None else (631 if protocol == "ipp" else 9100)
    notice = build_notice(ip, port, protocol, net.source_label(ip), guide_url, note,
                          fingerprint=fp)
    data = render_notice(notice, fmt, paper, native_qr, media=pwg.media_for(fp.media_default))
    summary = (
        f"[goblin] {ip}:{port} via {protocol.upper()} | {fmt} | {len(data)} bytes\n"
        f"One notice: {notice.headline}\n"
        + "\n".join(notice.lines)
        + f"\nQR and guide URL: {notice.url}\n"
        + "\n".join(notice.footer)
    )
    summary = "".join(char if char.isprintable() or char == "\n" else "?" for char in summary)
    return PrintPlan(ip, fp, notice.findings, protocol, port, fmt, data, summary, target, notice)


@contextmanager
def _audit_attempt(governor, target):
    audit = {"target": target}
    governor.audit("attempt", **audit)
    try:
        yield audit
    except KeyboardInterrupt:
        governor.audit(audit.get("status", "refused"), **audit, reason="interrupted")
        raise
    except (safety.PrintRefused, scope.ScopeError, EOFError) as exc:
        governor.audit("refused", **audit, reason=str(exc) or "confirmation interrupted")
        raise
    except Exception as exc:
        governor.audit("failed", **audit, reason=str(exc))
        raise
    else:
        governor.audit(audit["status"], **audit)


def _describe_plan(audit, plan):
    audit.update(ip=plan.ip, port=plan.port, protocol=plan.protocol,
                 format=plan.format, bytes=len(plan.data))


def execute_print(plan: PrintPlan, typed_address: str, authorized: bool,
                  governor=None, *, on_status=None) -> dict:
    governor = governor if governor is not None else safety.PrintGovernor()
    with _audit_attempt(governor, plan.target) as audit:
        return _execute(plan, typed_address, authorized, governor, audit, on_status)


def _execute(plan, typed_address, authorized, governor, audit, on_status):
    _describe_plan(audit, plan)
    if authorized is not True:
        raise safety.PrintRefused("Printing requires explicit authorization.")
    if typed_address != plan.ip:
        raise safety.PrintRefused("Address confirmation declined.")
    if str(scope.resolve_target(plan.ip)) != plan.ip:
        raise safety.PrintRefused("Print plan requires a resolved printer address.")
    if plan.format == "pwg" and plan.protocol != "ipp":
        raise safety.PrintRefused("PWG Raster requires IPP. Select --via ipp.")

    def stage(status):
        audit.update(status=status, note=PHYSICAL_PRINT_NOTE)
        if on_status is not None:
            on_status(dict(audit))

    # Serialize check through record so simultaneous GUI requests cannot bypass cooldown.
    with _PRINT_LOCK:
        governor.check(plan.ip, len(plan.data))
        try:
            if plan.protocol == "ipp":
                path = (plan.fingerprint.ipp_path if plan.port == 631 else None) or "/ipp/print"
                status, job_id = transports.send_ipp(
                    plan.ip, plan.data, MIME_TYPES[plan.format], plan.port, path,
                    on_submit=lambda: stage("submitted"),
                )
                audit.update(ipp_status=status, job_id=job_id)
                if status >= 0x0100:
                    raise OSError(f"Print-Job failed with IPP status 0x{status:04x}")
            else:
                transports.send_raw(plan.ip, plan.data, plan.port,
                                    on_submit=lambda: stage("submitted"))
        finally:
            # A transport error can occur after the printer has received the job.
            governor.record(plan.ip)
    if plan.protocol == "ipp":
        if status in (0, 1) and job_id is not None:
            stage("accepted")
            _track_job(plan, job_id, path, audit, stage)
        else:
            audit["tracking_error"] = "IPP did not return successful-ok with a job ID."
    return dict(audit)


def _track_job(plan, job_id, path, audit, stage):
    deadline = time.monotonic() + _JOB_POLL_SECONDS
    while (started := time.monotonic()) < deadline:
        try:
            attrs = ipp.get_job_attributes(plan.ip, job_id, plan.port, path,
                                           timeout=min(deadline - started, _JOB_POLL_INTERVAL))
            state = next(iter(attrs.get("job-state", [])), None)
            if type(state) is not int or state not in range(3, 10):
                raise ValueError("IPP did not report a recognized job state.")
        except (TimeoutError, ConnectionError, http.client.HTTPException) as exc:
            audit["tracking_error"] = str(exc) or type(exc).__name__
        except (OSError, ValueError) as exc:
            audit["tracking_error"] = str(exc)
            return
        else:
            audit.pop("tracking_error", None)
            reasons = [reason for reason in attrs.get("job-state-reasons", []) if isinstance(reason, str)]
            audit.update(job_state=state, job_state_reasons=reasons)
            if state == 9:
                impressions = next(iter(attrs.get("job-impressions-completed", [])), None)
                audit["job_impressions_completed"] = (
                    impressions if type(impressions) is int and impressions >= 0 else None
                )
                stage("completed")
                return
            if state in (7, 8):
                stage("failed")
                return
        next_poll = min(deadline, started + _JOB_POLL_INTERVAL)
        time.sleep(max(0, next_poll - time.monotonic()))
    if "job_state" in audit:
        stage("pending")


def print_status_text(report):
    status = report["status"]
    details = []
    if report.get("protocol") == "raw" and status == "submitted":
        details.append(f"raw port {report['port']} gives no confirmation")
    if report.get("job_id") is not None:
        details.append(f"IPP job {report['job_id']}")
    if report.get("job_state") is not None:
        state = report["job_state"]
        name = {3: "pending", 4: "pending-held", 5: "processing", 6: "processing-stopped",
                7: "canceled", 8: "aborted", 9: "completed"}[state]
        details.append(f"printer state {state} ({name})")
    if report.get("job_state_reasons"):
        details.append(", ".join(report["job_state_reasons"]))
    if report.get("job_impressions_completed") is not None:
        details.append(f"{report['job_impressions_completed']} impressions completed")
    if report.get("tracking_error"):
        details.append(report["tracking_error"])
    message = f"{status.capitalize()} ({', '.join(details)})." if details else f"{status.capitalize()}."
    return "".join(char if char.isprintable() else "?" for char in message)


def run_demo(args, *, identify=fingerprint_target, on_status=None):
    governor = safety.PrintGovernor()
    with _audit_attempt(governor, args.target) as audit:
        ip = str(scope.resolve_target(args.target))
        audit["ip"] = ip
        if not args.yes_i_am_authorized:
            raise safety.PrintRefused("Printing requires --yes-i-am-authorized.")
        plan = _plan(args.target, ip, identify, args.format, args.via, args.port,
                     args.guide_url, args.note, args.paper, not args.raster_qr)
        _describe_plan(audit, plan)
        governor.check(ip, len(plan.data))
        confirmed = safety.confirm(ip, plan.summary)
        return _execute(plan, ip if confirmed else "", True, governor, audit, on_status)


def discover(cidr, ports=discovery.DEFAULT_PORTS):
    return {"hosts": [asdict(host) for host in discovery.discover(cidr, ports)]}


def identify(target, *, probe=fingerprint_target):
    fp = probe(target)
    report = asdict(fp)
    report.update(model=fp.model, serial=fp.serial, media_default=fp.media_default, services=service_lines(fp),
                  findings=[asdict(item) for item in observed_findings(fp, net.source_ip(fp.ip))])
    return json.loads(json.dumps(report, default=lambda raw: raw.hex()))


def baseline(targets, ports, out_path, label="", *, expect="deny", allow=()):
    return verification.baseline(targets, ports, out_path, label, expect=expect, allow=allow)


def snapshot(targets, ports, out_path, label=""):
    return verification.baseline(targets, ports, out_path, label, reference=True)


def verify(baseline_path, *, reference=None, printer_online=False):
    return verification.compare(baseline_path, reference=reference, printer_online=printer_online)
