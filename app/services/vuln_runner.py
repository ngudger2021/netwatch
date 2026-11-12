"""Runs vulners and/or Nuclei in a background thread, one run at a time.

Status is kept in app_settings (key 'vuln_status') so the page can poll it and it survives a page reload.
A run is refused while a scan job is queued or running, so the Pi is never doing discovery and checks at once.
"""
from __future__ import annotations

import json
import logging
import threading
from pathlib import Path

from app.config import Settings
from app.database import connect
from app.database.connection import utc_now
from app.services import jobs, vuln_scan
from app.services.bootstrap import get_setting, set_setting

log = logging.getLogger("netwatch.vuln")
STATUS_KEY = "vuln_status"
ALLOWED_TOOLS = ("vulners", "nuclei")
_thread_lock = threading.Lock()


class VulnRunRefused(RuntimeError):
    pass


def read_status(conn) -> dict:
    raw = get_setting(conn, STATUS_KEY, "")
    if not raw:
        return {"state": "idle"}
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {"state": "idle"}


def _write_status(conn, **fields) -> None:
    current = read_status(conn)
    current.update(fields)
    set_setting(conn, STATUS_KEY, json.dumps(current, default=str))


def validate_request(settings: Settings, tools: list[str], conn) -> None:
    if not tools or any(t not in ALLOWED_TOOLS for t in tools):
        raise VulnRunRefused(f"tools must be a subset of {list(ALLOWED_TOOLS)}")
    for tool in tools:
        if tool == "vulners" and not settings.vulnerability.vulners_enabled:
            raise VulnRunRefused("vulners is disabled in [vulnerability] vulners_enabled (it sends data to vulners.com)")
        if tool == "nuclei" and not settings.vulnerability.nuclei_enabled:
            raise VulnRunRefused("nuclei is disabled in [vulnerability] nuclei_enabled")
    if read_status(conn).get("state") == "running":
        raise VulnRunRefused("a vulnerability run is already in progress")
    if jobs.active_job(conn) is not None:
        raise VulnRunRefused("a scan is queued or running; try again when it finishes")


def start(settings: Settings, tools: list[str], device_ids: list[int] | None, *, conn) -> dict:
    with _thread_lock:  # check-and-set must be atomic so two requests cannot both start a run
        validate_request(settings, tools, conn)
        _write_status(conn, state="running", tools=tools, started=utc_now(), finished=None, result=None,
                      error="", devices=device_ids or "all")
        thread = threading.Thread(target=_run, args=(settings, tools, device_ids), name="vuln-run", daemon=True)
        thread.start()
    return read_status(conn)


def _run(settings: Settings, tools: list[str], device_ids: list[int] | None) -> None:
    conn = connect(settings.db_path)
    try:
        with jobs.runner_lock(settings.scan_lock_path) as acquired:
            if not acquired:
                _write_status(conn, state="error", error="a scan is holding the runner lock; try again later",
                              finished=utc_now())
                return
            scans_dir = Path(settings.app.data_dir) / "scans"
            scans_dir.mkdir(parents=True, exist_ok=True)
            specs = vuln_scan.load_devices(conn, device_ids)
            result: dict = {"devices": len(specs)}
            try:
                if "vulners" in tools:
                    if not vuln_scan.vulners_script_installed(settings.scanning.nmap_path):
                        raise vuln_scan.VulnToolError("vulners NSE script is not installed (see README)")
                    result["vulners"] = vuln_scan.run_vulners(conn, settings, specs, scans_dir)
                if "nuclei" in tools:
                    binary = vuln_scan.nuclei_path()
                    if binary is None:
                        raise vuln_scan.VulnToolError("nuclei is not installed (sudo apt install nuclei)")
                    result["nuclei"] = vuln_scan.run_nuclei(conn, settings, specs, scans_dir, binary)
                _write_status(conn, state="done", finished=utc_now(), result=result, error="")
            except vuln_scan.VulnToolError as exc:
                _write_status(conn, state="error", finished=utc_now(), error=str(exc), result=result)
    except Exception as exc:  # never let a background thread die silently
        log.exception("vulnerability run failed")
        try:
            _write_status(conn, state="error", finished=utc_now(), error=type(exc).__name__)
        except Exception:
            pass
    finally:
        conn.close()
