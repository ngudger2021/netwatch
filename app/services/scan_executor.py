"""Executes one scan job end-to-end: nmap per unit -> parse -> ingest -> status.

Unit = one nmap invocation. For profile scans it is a whole configured network
(absence detection applies). For custom scans with explicit targets, each
target is its own unit and absence detection is disabled because the scan did
not cover the whole network.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import os
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path

from app.config import Settings
from app.database.connection import transaction, utc_now
from app.scanners import nmap_parser
from app.scanners.neighbors import is_local_network, neighbour_macs
from app.scanners.nmap_runner import NmapUnavailable, build_command, run_command
from app.scanners.targets import build_nmap_args
from app.services import jobs
from app.services.ingest import PortScope, ingest_unit

log = logging.getLogger("netwatch.scan")


@dataclass
class Unit:
    network_id: int | None
    network_cidr: str
    target: str
    absence_check: bool


def _network_for(conn: sqlite3.Connection, target: str) -> sqlite3.Row | None:
    net = ipaddress.ip_network(target, strict=False)
    for row in conn.execute("SELECT * FROM networks WHERE enabled = 1"):
        if net.subnet_of(ipaddress.ip_network(row["cidr"])):
            return row
    return None


def plan_units(conn: sqlite3.Connection, params: dict) -> list[Unit]:
    units: list[Unit] = []
    targets = params.get("targets") or []
    if targets:
        for t in targets:
            row = _network_for(conn, t)
            units.append(Unit(row["id"] if row else None, row["cidr"] if row else t, t, absence_check=False))
    else:
        for cidr in params.get("networks") or []:
            row = conn.execute("SELECT * FROM networks WHERE cidr = ?", (cidr,)).fetchone()
            units.append(Unit(row["id"] if row else None, cidr, cidr, absence_check=True))
    return units


def _port_plan(profile: str, params: dict, settings: Settings) -> tuple[PortScope, str]:
    ports = params.get("ports") or ""
    if profile == "quick":
        return PortScope("none"), ""
    if profile == "standard":
        return PortScope("top"), ""
    if profile == "detailed":
        spec = ports or settings.scanning.default_detailed_ports
        return PortScope("explicit", _expand(spec)), spec
    # custom
    if ports:
        return PortScope("explicit", _expand(ports)), ports
    return PortScope("top"), ""


def _expand(spec: str) -> frozenset[int]:
    out: set[int] = set()
    for item in spec.split(","):
        if "-" in item:
            lo, hi = item.split("-")
            out.update(range(int(lo), int(hi) + 1))
        elif item:
            out.add(int(item))
    return frozenset(out)


def execute_job(conn: sqlite3.Connection, settings: Settings, job: sqlite3.Row) -> str:
    """Run a claimed job (status already 'running'). Returns final status string."""
    job_id = job["id"]
    profile = job["profile"]
    params = json.loads(job["params"] or "{}")
    scans_dir = Path(settings.app.data_dir) / "scans"
    scans_dir.mkdir(parents=True, exist_ok=True)
    cfg = settings.scanning

    units = plan_units(conn, params)
    if not units:
        jobs.finish(conn, job_id, "failed", error="no scan units resolved")
        return "failed"

    scope, port_spec = _port_plan(profile, params, settings)
    parallelism = params.get("concurrency") or cfg.max_parallelism
    host_timeout = params.get("host_timeout") or (
        cfg.host_timeout_seconds * 2 if profile == "detailed" else cfg.host_timeout_seconds)
    service_detection = params.get("service_detection", True)
    deadline = time.monotonic() + cfg.job_timeout_seconds

    local_cache: dict[str, str] | None = None
    outcomes: list[str] = []
    total_up = 0
    total_hosts = 0
    last_error = ""
    nmap_args_seen = ""
    jobs.set_progress(conn, job_id, f"0/{len(units)} units", f"job {job_id}: {profile} scan started")

    for idx, unit in enumerate(units, start=1):
        if jobs.cancel_requested(conn, job_id):
            outcomes.append("cancelled")
            break
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            outcomes.append("timeout")
            last_error = "job timeout reached"
            break

        jobs.set_progress(conn, job_id, f"{idx}/{len(units)} scanning {unit.target}")
        outfile = scans_dir / f"job{job_id}-{idx}.xml"
        stderr_file = scans_dir / f"job{job_id}-{idx}.err"
        argv = build_nmap_args(
            profile, unit.target, outfile=str(outfile), ports=port_spec,
            top_ports=cfg.top_ports, default_detailed_ports=cfg.default_detailed_ports,
            privileged=cfg.privileged, parallelism=parallelism, host_timeout=host_timeout,
            service_detection=service_detection and profile != "quick",
        )
        nmap_args_seen = " ".join(argv)
        try:
            cmd = build_command(cfg, argv)
        except NmapUnavailable as exc:
            jobs.finish(conn, job_id, "failed", error=str(exc))
            return "failed"

        result = run_command(cmd, timeout=remaining, stderr_path=str(stderr_file),
                             should_cancel=lambda: jobs.cancel_requested(conn, job_id))
        if result.cancelled:
            outcomes.append("cancelled")
            _record_unit(conn, job_id, unit, "cancelled", "cancelled by operator", 0)
            break
        if result.timed_out:
            outcomes.append("timeout")
            last_error = f"{unit.target}: nmap exceeded the timeout"
            _record_unit(conn, job_id, unit, "timeout", last_error, 0)
            _fail_event(conn, job_id, unit, last_error)
            continue
        if not result.ok:
            err = (result.stderr_tail or "nmap exited with an error").strip().splitlines()[-1:] or ["nmap failed"]
            last_error = f"{unit.target}: {err[0][:300]}"
            outcomes.append("failed")
            _record_unit(conn, job_id, unit, "failed", last_error, 0)
            _fail_event(conn, job_id, unit, last_error)
            continue

        try:
            report = nmap_parser.parse_nmap_xml(
                outfile.read_text(encoding="utf-8", errors="replace"),
                ports_scanned=scope.mode != "none")
        except (OSError, nmap_parser.NmapParseError) as exc:
            last_error = f"{unit.target}: could not parse results ({exc})"
            outcomes.append("failed")
            _record_unit(conn, job_id, unit, "failed", last_error, 0)
            _fail_event(conn, job_id, unit, last_error)
            continue

        local = bool(unit.network_id) and is_local_network(unit.network_cidr)
        if unit.network_id:
            with transaction(conn):
                conn.execute("UPDATE networks SET is_local = ? WHERE id = ?", (int(local), unit.network_id))
        macs = None
        if local:
            if local_cache is None:
                local_cache = neighbour_macs()
            macs = local_cache

        ingest_unit(
            conn, job_id=job_id, network_id=unit.network_id, report=report, observed_at=utc_now(),
            ports=scope, absence_check=unit.absence_check and unit.network_id is not None,
            offline_threshold=settings.change.offline_threshold,
            recent_days=settings.change.recent_days, local_macs=macs,
            oui_file=cfg.oui_file,
        )
        try:
            os.remove(outfile)  # the parsed results are in the database; keep the SD card lean
        except OSError:
            pass
        _record_unit(conn, job_id, unit, "ok", "", report.hosts_up)
        outcomes.append("ok")
        total_up += report.hosts_up
        total_hosts += report.hosts_total
        jobs.set_progress(conn, job_id, f"{idx}/{len(units)} done",
                          f"{unit.target}: {report.hosts_up} hosts up ({report.elapsed_seconds:.0f}s)")

    if "cancelled" in outcomes:
        status = "cancelled"
    elif outcomes and all(o == "ok" for o in outcomes) and len(outcomes) == len(units):
        status = "completed"
    elif "ok" in outcomes:
        status = "partial"
    elif outcomes and all(o == "timeout" for o in outcomes):
        status = "timeout"
    else:
        status = "failed"
    if status not in ("completed",) and not last_error:
        last_error = "not all networks were scanned"
    jobs.finish(conn, job_id, status, error=last_error if status != "completed" else "",
                hosts_up=total_up, hosts_total=total_hosts, nmap_args=nmap_args_seen)
    _event_row(conn, job_id, status, total_up)
    return status


def _record_unit(conn, job_id: int, unit: Unit, status: str, error: str, hosts_up: int) -> None:
    with transaction(conn):
        conn.execute(
            """INSERT INTO scan_job_networks(job_id, network_id, cidr, status, error, hosts_up)
               VALUES (?,?,?,?,?,?)
               ON CONFLICT(job_id, cidr) DO UPDATE SET status=excluded.status, error=excluded.error,
               hosts_up=excluded.hosts_up""",
            (job_id, unit.network_id, unit.target, status, error[:500], hosts_up))


def _fail_event(conn, job_id: int, unit: Unit, message: str) -> None:
    now = utc_now()
    with transaction(conn):
        conn.execute(
            "INSERT INTO events(created_at, type, severity, job_id, title, details) VALUES (?,?,?,?,?,?)",
            (now, "scan_failed", "high", job_id, f"Scan failed for {unit.target}: {message[:200]}",
             json.dumps({"target": unit.target})))


def _event_row(conn, job_id: int, status: str, hosts_up: int) -> None:
    with transaction(conn):
        conn.execute(
            "INSERT INTO events(created_at, type, severity, job_id, title, details) VALUES (?,?,?,?,?,?)",
            (utc_now(), "scan_completed", "info", job_id,
             f"Scan #{job_id} {status}: {hosts_up} hosts responded",
             json.dumps({"status": status, "hosts_up": hosts_up})))
