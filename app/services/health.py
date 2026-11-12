"""Host and application health for the Raspberry Pi (psutil + sysfs, no root needed)."""
from __future__ import annotations

import os
import shutil
import sqlite3
import subprocess
import time
from pathlib import Path

import psutil

from app.database.connection import utc_now
from app.services.bootstrap import get_setting

SERVICE_UNITS = ("kali-netwatch-web.service", "kali-netwatch-scheduler.service")


def cpu_temperature() -> float | None:
    try:
        raw = Path("/sys/class/thermal/thermal_zone0/temp").read_text().strip()
        return round(int(raw) / 1000.0, 1)
    except (OSError, ValueError):
        pass
    try:
        temps = psutil.sensors_temperatures() or {}
        for entries in temps.values():
            if entries:
                return round(entries[0].current, 1)
    except (AttributeError, OSError):
        pass
    return None


def interfaces() -> list[dict]:
    out = []
    stats = psutil.net_if_stats()
    addrs = psutil.net_if_addrs()
    for name, st in stats.items():
        if name == "lo":
            continue
        ipv4 = [a.address for a in addrs.get(name, []) if a.family.name == "AF_INET"]
        out.append({"name": name, "up": bool(st.isup), "speed_mbps": st.speed, "ipv4": ipv4})
    return out


def service_state(unit: str) -> str:
    exe = shutil.which("systemctl")
    if not exe:
        return "unknown"
    try:
        proc = subprocess.run([exe, "is-active", unit], capture_output=True, text=True,
                              timeout=5, shell=False, check=False)
        return proc.stdout.strip() or "unknown"
    except (OSError, subprocess.TimeoutExpired):
        return "unknown"


def system_snapshot(conn: sqlite3.Connection, data_dir: Path, *, include_services: bool = True) -> dict:
    mem = psutil.virtual_memory()
    disk_path = str(data_dir if data_dir.exists() else Path("/"))
    disk = psutil.disk_usage(disk_path)
    db_size = 0
    for suffix in ("", "-wal", "-shm"):
        p = Path(str(data_dir / "netwatch.db") + suffix)
        if p.exists():
            db_size += p.stat().st_size
    last_scan = conn.execute(
        "SELECT duration_seconds, finished_at FROM scan_jobs WHERE duration_seconds IS NOT NULL "
        "ORDER BY id DESC LIMIT 1").fetchone()
    heartbeat = get_setting(conn, "scheduler_heartbeat", "")
    snapshot = {
        "timestamp": utc_now(),
        "cpu_percent": psutil.cpu_percent(interval=None),
        "load_average": list(os.getloadavg()),
        "memory": {"percent": mem.percent, "used_mb": round(mem.used / 1048576, 1),
                   "total_mb": round(mem.total / 1048576, 1)},
        "disk": {"path": disk_path, "percent": disk.percent, "used_gb": round(disk.used / 1073741824, 2),
                 "total_gb": round(disk.total / 1073741824, 2)},
        "temperature_c": cpu_temperature(),
        "uptime_seconds": int(time.time() - psutil.boot_time()),
        "interfaces": interfaces(),
        "database": {"size_mb": round(db_size / 1048576, 2)},
        "last_scan_duration_seconds": last_scan["duration_seconds"] if last_scan else None,
        "scheduler_heartbeat": heartbeat or None,
        "scheduler_healthy": _recent(heartbeat, 120),
    }
    if include_services:
        snapshot["services"] = {unit: service_state(unit) for unit in SERVICE_UNITS}
    return snapshot


def _recent(stamp: str, max_age: int) -> bool:
    if not stamp:
        return False
    from app.database.connection import parse_ts
    from datetime import datetime, timezone
    ts = parse_ts(stamp)
    return ts is not None and (datetime.now(timezone.utc) - ts).total_seconds() <= max_age
