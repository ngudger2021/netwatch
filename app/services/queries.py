"""Read-side queries for the API, pages and reports. All SQL is parameterised;
sort columns and filter names are whitelisted."""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone

from app.services.audit import risk_level
from app.services.bootstrap import get_setting

DEVICE_SORTS = {
    "ip": "d.current_ip", "hostname": "d.hostname", "status": "d.status", "last_seen": "d.last_seen",
    "first_seen": "d.first_seen", "risk": "d.risk_score", "ports": "port_count", "network": "n.cidr",
    "vendor": "d.vendor", "type": "d.device_type",
}
RISK_BANDS = {"low": (0, 24), "medium": (25, 59), "high": (60, 100)}
SCHEDULE_KEYS = {"discovery": "discovery_minutes", "standard": "standard_hours", "summary": "summary_hours"}


def _page(page: int, size: int) -> tuple[int, int]:
    page = max(1, int(page))
    size = min(max(1, int(size)), 200)
    return page, size


def _ip_key(ip: str) -> tuple:
    try:
        return tuple(int(x) for x in ip.split("."))
    except ValueError:
        return (999,)


def list_devices(conn: sqlite3.Connection, *, q: str = "", network: str = "", vendor: str = "",
                 device_type: str = "", status: str = "", risk: str = "", trusted: str = "",
                 sort: str = "ip", order: str = "asc", page: int = 1, size: int = 50) -> dict:
    page, size = _page(page, size)
    where, args = ["1=1"], []
    if q:
        where.append("(d.hostname LIKE ? OR d.custom_name LIKE ? OR d.current_ip LIKE ? OR d.mac LIKE ? "
                     "OR d.vendor LIKE ? OR d.description LIKE ?)")
        args += [f"%{q}%"] * 6
    if network:
        where.append("n.cidr = ?"); args.append(network)
    if vendor:
        where.append("d.vendor LIKE ?"); args.append(f"%{vendor}%")
    if device_type:
        where.append("d.device_type = ?"); args.append(device_type)
    if status in ("online", "offline", "unknown"):
        where.append("d.status = ?"); args.append(status)
    if risk in RISK_BANDS:
        lo, hi = RISK_BANDS[risk]
        where.append("d.risk_score BETWEEN ? AND ?"); args += [lo, hi]
    if trusted in ("0", "1"):
        where.append("d.trusted = ?"); args.append(int(trusted))
    col = DEVICE_SORTS.get(sort, "d.current_ip")
    direction = "DESC" if order == "desc" else "ASC"
    base = f"""FROM devices d LEFT JOIN networks n ON n.id = d.network_id
               LEFT JOIN (SELECT device_id, COUNT(*) AS port_count FROM open_ports
                          WHERE state='open' GROUP BY device_id) p ON p.device_id = d.id
               WHERE {' AND '.join(where)}"""
    total = conn.execute(f"SELECT COUNT(*) {base}", args).fetchone()[0]
    select = f"SELECT d.*, n.cidr AS network, COALESCE(p.port_count, 0) AS port_count {base}"
    if sort == "ip":
        # Numeric IPv4 ordering cannot be expressed portably in SQLite; the filtered set is
        # small (one row per device), so sort it fully and then page.
        rows = conn.execute(select, args).fetchall()
        rows = sorted(rows, key=lambda r: (_ip_key(r["current_ip"]), r["id"]), reverse=direction == "DESC")
        rows = rows[(page - 1) * size: (page - 1) * size + size]
    else:
        rows = conn.execute(f"{select} ORDER BY {col} {direction}, d.id LIMIT ? OFFSET ?",
                            [*args, size, (page - 1) * size]).fetchall()
    items = []
    for r in rows:
        item = _device_dict(r)
        item["risk_level"] = risk_level(r["risk_score"])
        items.append(item)
    return {"items": items, "total": total, "page": page, "size": size,
            "pages": max(1, (total + size - 1) // size)}


def _device_dict(r: sqlite3.Row) -> dict:
    keys = r.keys()
    return {
        "id": r["id"], "ip": r["current_ip"], "hostname": r["hostname"], "custom_name": r["custom_name"],
        "mac": r["mac"], "mac_randomized": bool(r["mac_randomized"]), "vendor": r["vendor"],
        "network": r["network"] if "network" in keys else None,
        "device_type": r["device_type"], "status": r["status"], "last_seen": r["last_seen"],
        "first_seen": r["first_seen"], "trusted": bool(r["trusted"]), "description": r["description"],
        "notes": r["notes"] if "notes" in keys else "", "risk_score": r["risk_score"],
        "port_count": r["port_count"] if "port_count" in keys else None,
    }


def device_detail(conn: sqlite3.Connection, device_id: int) -> dict | None:
    row = conn.execute(
        "SELECT d.*, n.cidr AS network FROM devices d LEFT JOIN networks n ON n.id = d.network_id WHERE d.id = ?",
        (device_id,)).fetchone()
    if row is None:
        return None
    detail = _device_dict(row)
    detail["ip_history"] = [dict(r) for r in conn.execute(
        "SELECT ip, first_seen, last_seen FROM device_addresses WHERE device_id = ? ORDER BY last_seen DESC", (device_id,))]
    detail["ports"] = [dict(r) for r in conn.execute(
        "SELECT port, protocol, state, service, product, version, extrainfo, first_seen, last_seen, closed_at "
        "FROM open_ports WHERE device_id = ? ORDER BY state DESC, port", (device_id,))]
    detail["findings"] = [dict(r) for r in conn.execute(
        "SELECT id, rule_key, port, title, description, severity, weight, service, evidence, remediation, "
        "status, first_detected, last_detected, resolved_at FROM security_findings WHERE device_id = ? "
        "ORDER BY status, CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 "
        "WHEN 'low' THEN 3 ELSE 4 END, port", (device_id,))]
    detail["risk_explanation"] = [
        {"title": f["title"], "port": f["port"], "weight": f["weight"], "severity": f["severity"]}
        for f in detail["findings"] if f["status"] == "open" and f["weight"] > 0]
    detail["risk_level"] = risk_level(row["risk_score"])
    detail["availability"] = availability(conn, device_id, days=7)
    detail["events"] = [dict(r) for r in conn.execute(
        "SELECT id, created_at, type, severity, title FROM events WHERE device_id = ? "
        "ORDER BY id DESC LIMIT 100", (device_id,))]
    detail["scans"] = [dict(r) for r in conn.execute(
        """SELECT r.observed_at, r.ip, r.ports_scanned, j.id AS job_id, j.profile, j.status
           FROM scan_results r JOIN scan_jobs j ON j.id = r.job_id
           WHERE r.device_id = ? ORDER BY r.id DESC LIMIT 50""", (device_id,))]
    detail["service_history"] = [dict(r) for r in conn.execute(
        "SELECT port, service, product, version, observed_at FROM service_observations "
        "WHERE device_id = ? ORDER BY id DESC LIMIT 100", (device_id,))]
    return detail


def availability(conn: sqlite3.Connection, device_id: int, days: int = 7) -> dict:
    since = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    row = conn.execute(
        "SELECT SUM(status='online') AS online, COUNT(*) AS total FROM device_observations "
        "WHERE device_id = ? AND observed_at >= ?", (device_id, since)).fetchone()
    total = row["total"] or 0
    online = row["online"] or 0
    return {"days": days, "observations": total, "online": online,
            "percent": round(100 * online / total, 1) if total else None}


def dashboard(conn: sqlite3.Connection, settings) -> dict:
    now = datetime.now(timezone.utc)
    day_ago = (now - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%SZ")
    fortnight = (now - timedelta(days=14)).strftime("%Y-%m-%dT%H:%M:%SZ")
    day_hours = (now - timedelta(hours=48)).strftime("%Y-%m-%dT%H:%M:%SZ")

    counts = conn.execute(
        """SELECT COUNT(*) AS total, SUM(status='online') AS online, SUM(status='offline') AS offline,
                  SUM(risk_score >= 60) AS high_risk FROM devices""").fetchone()
    stats = {
        "devices_total": counts["total"] or 0,
        "online": counts["online"] or 0,
        "offline": counts["offline"] or 0,
        "unknown": (counts["total"] or 0) - (counts["online"] or 0) - (counts["offline"] or 0),
        "new_devices_24h": conn.execute("SELECT COUNT(*) FROM events WHERE type='device_new' AND created_at >= ?",
                                        (day_ago,)).fetchone()[0],
        "open_ports": conn.execute("SELECT COUNT(*) FROM open_ports WHERE state='open'").fetchone()[0],
        "high_risk_devices": counts["high_risk"] or 0,
        "open_findings": conn.execute("SELECT COUNT(*) FROM security_findings WHERE status='open'").fetchone()[0],
    }
    last = conn.execute(
        "SELECT finished_at, duration_seconds FROM scan_jobs WHERE status IN ('completed','partial') "
        "ORDER BY id DESC LIMIT 1").fetchone()
    running = conn.execute(
        "SELECT id, profile, status, progress, started_at, created_at FROM scan_jobs "
        "WHERE status IN ('queued','running') ORDER BY id LIMIT 1").fetchone()
    stats["last_successful_scan"] = last["finished_at"] if last else None
    stats["last_scan_duration"] = last["duration_seconds"] if last else None
    stats["scan_running"] = dict(running) if running else None
    stats["next_scheduled"] = next_scheduled(conn, settings)

    subnets = [dict(r) for r in conn.execute(
        """SELECT n.cidr, COUNT(d.id) AS devices, SUM(d.status='online') AS online
           FROM networks n LEFT JOIN devices d ON d.network_id = n.id GROUP BY n.id ORDER BY n.cidr""")]
    avail = [dict(r) for r in conn.execute(
        """SELECT substr(observed_at,1,13) AS hour, SUM(status='online') AS online, COUNT(*) AS total
           FROM device_observations WHERE observed_at >= ? GROUP BY hour ORDER BY hour""", (day_hours,))]
    discoveries = [dict(r) for r in conn.execute(
        """SELECT substr(created_at,1,10) AS day, COUNT(*) AS count FROM events
           WHERE type='device_new' AND created_at >= ? GROUP BY day ORDER BY day""", (fortnight,))]
    ports_by_service = [dict(r) for r in conn.execute(
        """SELECT CASE WHEN service='' THEN 'unknown' ELSE service END AS service, COUNT(*) AS count
           FROM open_ports WHERE state='open' GROUP BY service ORDER BY count DESC LIMIT 12""")]
    findings_by_sev = [dict(r) for r in conn.execute(
        "SELECT severity, COUNT(*) AS count FROM security_findings WHERE status='open' GROUP BY severity")]
    activity = [dict(r) for r in conn.execute(
        "SELECT id, created_at, type, severity, title FROM events ORDER BY id DESC LIMIT 30")]
    return {
        "stats": stats,
        "charts": {
            "online_vs_offline": {"online": stats["online"], "offline": stats["offline"], "unknown": stats["unknown"]},
            "devices_per_subnet": subnets,
            "availability": avail,
            "new_discoveries": discoveries,
            "ports_by_service": ports_by_service,
            "findings_by_severity": findings_by_sev,
        },
        "activity": activity,
    }


def next_scheduled(conn: sqlite3.Connection, settings) -> dict:
    out = {}
    if not settings.schedule.enabled:
        return {"enabled": False}
    intervals = {
        "quick": timedelta(minutes=settings.schedule.discovery_minutes),
        "standard": timedelta(hours=settings.schedule.standard_hours),
    }
    for name, interval in intervals.items():
        last = get_setting(conn, f"sched_last:{name}", "")
        if last:
            nxt = datetime.strptime(last, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc) + interval
            out[name] = nxt.strftime("%Y-%m-%dT%H:%M:%SZ")
        else:
            out[name] = "pending (first run after scheduler start)"
    out["enabled"] = True
    return out


def list_findings(conn: sqlite3.Connection, *, status: str = "open", severity: str = "",
                  page: int = 1, size: int = 50) -> dict:
    page, size = _page(page, size)
    where, args = ["1=1"], []
    if status in ("open", "resolved", "acknowledged"):
        where.append("f.status = ?"); args.append(status)
    if severity:
        where.append("f.severity = ?"); args.append(severity)
    base = f"FROM security_findings f JOIN devices d ON d.id = f.device_id WHERE {' AND '.join(where)}"
    total = conn.execute(f"SELECT COUNT(*) {base}", args).fetchone()[0]
    rows = conn.execute(
        f"""SELECT f.*, d.current_ip AS ip, d.hostname, d.custom_name, d.trusted {base}
            ORDER BY CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2
            WHEN 'low' THEN 3 ELSE 4 END, f.last_detected DESC LIMIT ? OFFSET ?""",
        [*args, size, (page - 1) * size]).fetchall()
    return {"items": [dict(r) for r in rows], "total": total, "page": page, "size": size,
            "pages": max(1, (total + size - 1) // size)}


def list_events(conn: sqlite3.Connection, *, type_: str = "", severity: str = "", page: int = 1, size: int = 50) -> dict:
    page, size = _page(page, size)
    where, args = ["1=1"], []
    if type_:
        where.append("e.type = ?"); args.append(type_)
    if severity:
        where.append("e.severity = ?"); args.append(severity)
    base = f"FROM events e WHERE {' AND '.join(where)}"
    total = conn.execute(f"SELECT COUNT(*) {base}", args).fetchone()[0]
    rows = conn.execute(f"SELECT e.* {base} ORDER BY e.id DESC LIMIT ? OFFSET ?",
                        [*args, size, (page - 1) * size]).fetchall()
    items = []
    for r in rows:
        d = dict(r)
        try:
            d["details"] = json.loads(d["details"] or "{}")
        except json.JSONDecodeError:
            d["details"] = {}
        items.append(d)
    return {"items": items, "total": total, "page": page, "size": size,
            "pages": max(1, (total + size - 1) // size)}


def list_scans(conn: sqlite3.Connection, page: int = 1, size: int = 25) -> dict:
    page, size = _page(page, size)
    total = conn.execute("SELECT COUNT(*) FROM scan_jobs").fetchone()[0]
    rows = conn.execute("SELECT * FROM scan_jobs ORDER BY id DESC LIMIT ? OFFSET ?",
                        (size, (page - 1) * size)).fetchall()
    return {"items": [dict(r) for r in rows], "total": total, "page": page, "size": size,
            "pages": max(1, (total + size - 1) // size)}


def scan_detail(conn: sqlite3.Connection, job_id: int) -> dict | None:
    row = conn.execute("SELECT * FROM scan_jobs WHERE id = ?", (job_id,)).fetchone()
    if row is None:
        return None
    out = dict(row)
    out["params"] = json.loads(out["params"] or "{}")
    out["units"] = [dict(r) for r in conn.execute(
        "SELECT cidr, status, error, hosts_up FROM scan_job_networks WHERE job_id = ?", (job_id,))]
    out["events"] = [dict(r) for r in conn.execute(
        "SELECT id, created_at, type, severity, title FROM events WHERE job_id = ? ORDER BY id DESC LIMIT 100",
        (job_id,))]
    return out


def list_networks(conn: sqlite3.Connection) -> list[dict]:
    rows = conn.execute(
        """SELECT n.*, COUNT(d.id) AS devices, SUM(d.status='online') AS online
           FROM networks n LEFT JOIN devices d ON d.network_id = n.id GROUP BY n.id ORDER BY n.cidr""").fetchall()
    return [dict(r) for r in rows]


def list_notifications(conn: sqlite3.Connection, page: int = 1, size: int = 50) -> dict:
    page, size = _page(page, size)
    total = conn.execute("SELECT COUNT(*) FROM notification_history").fetchone()[0]
    rows = conn.execute("SELECT * FROM notification_history ORDER BY id DESC LIMIT ? OFFSET ?",
                        (size, (page - 1) * size)).fetchall()
    return {"items": [dict(r) for r in rows], "total": total, "page": page, "size": size,
            "pages": max(1, (total + size - 1) // size)}


def summary_stats(conn: sqlite3.Connection) -> dict:
    counts = conn.execute(
        "SELECT COUNT(*) AS total, SUM(status='online') AS online, SUM(status='offline') AS offline FROM devices").fetchone()
    day_ago = (datetime.now(timezone.utc) - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%SZ")
    last = conn.execute("SELECT finished_at FROM scan_jobs WHERE status IN ('completed','partial') "
                        "ORDER BY id DESC LIMIT 1").fetchone()
    return {
        "devices": counts["total"] or 0, "online": counts["online"] or 0, "offline": counts["offline"] or 0,
        "new_24h": conn.execute("SELECT COUNT(*) FROM events WHERE type='device_new' AND created_at >= ?",
                                (day_ago,)).fetchone()[0],
        "open_ports": conn.execute("SELECT COUNT(*) FROM open_ports WHERE state='open'").fetchone()[0],
        "open_findings": conn.execute("SELECT COUNT(*) FROM security_findings WHERE status='open'").fetchone()[0],
        "high_findings": conn.execute("SELECT COUNT(*) FROM security_findings WHERE status='open' "
                                      "AND severity IN ('high','critical')").fetchone()[0],
        "last_scan": last["finished_at"] if last else "never",
    }
