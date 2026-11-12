"""Exports: device inventory, open ports, security findings, recent changes, scan statistics.

Formats: csv, json, html. Every dataset is built with parameterised queries and
contains no secrets (notification tokens and password hashes are never selected).
"""
from __future__ import annotations

import csv
import html
import io
import json
import sqlite3
from datetime import datetime, timezone

from app.database.connection import utc_now
from app.services.audit import risk_level

DATASETS = ("inventory", "ports", "findings", "changes", "statistics")
FORMATS = ("csv", "json", "html")


def dataset(conn: sqlite3.Connection, name: str) -> list[dict]:
    if name == "inventory":
        rows = conn.execute(
            """SELECT d.id, d.current_ip AS ip, d.hostname, d.custom_name, d.mac, d.mac_randomized,
                      d.vendor, n.cidr AS network, d.device_type, d.status, d.first_seen, d.last_seen,
                      d.trusted, d.risk_score, d.description,
                      (SELECT COUNT(*) FROM open_ports p WHERE p.device_id = d.id AND p.state='open') AS open_ports
               FROM devices d LEFT JOIN networks n ON n.id = d.network_id ORDER BY d.current_ip""").fetchall()
        out = [dict(r) for r in rows]
        for r in out:
            r["risk_level"] = risk_level(r["risk_score"])
            r["mac_randomized"] = bool(r["mac_randomized"])
            r["trusted"] = bool(r["trusted"])
        return out
    if name == "ports":
        rows = conn.execute(
            """SELECT d.current_ip AS ip, d.hostname, p.port, p.protocol, p.state, p.service, p.product,
                      p.version, p.first_seen, p.last_seen, p.closed_at
               FROM open_ports p JOIN devices d ON d.id = p.device_id ORDER BY d.current_ip, p.port""").fetchall()
        return [dict(r) for r in rows]
    if name == "findings":
        rows = conn.execute(
            """SELECT d.current_ip AS ip, d.hostname, f.severity, f.title, f.port, f.service, f.status,
                      f.weight, f.evidence, f.remediation, f.first_detected, f.last_detected, f.resolved_at
               FROM security_findings f JOIN devices d ON d.id = f.device_id
               ORDER BY f.status, f.severity DESC, d.current_ip""").fetchall()
        return [dict(r) for r in rows]
    if name == "changes":
        rows = conn.execute(
            "SELECT created_at, type, severity, title FROM events ORDER BY id DESC LIMIT 1000").fetchall()
        return [dict(r) for r in rows]
    if name == "statistics":
        return [{"metric": k, "value": v} for k, v in _statistics(conn).items()]
    raise KeyError(name)


def _statistics(conn: sqlite3.Connection) -> dict:
    def one(sql: str):
        return conn.execute(sql).fetchone()[0]
    return {
        "devices": one("SELECT COUNT(*) FROM devices"),
        "devices_online": one("SELECT COUNT(*) FROM devices WHERE status='online'"),
        "devices_offline": one("SELECT COUNT(*) FROM devices WHERE status='offline'"),
        "open_ports": one("SELECT COUNT(*) FROM open_ports WHERE state='open'"),
        "open_findings": one("SELECT COUNT(*) FROM security_findings WHERE status='open'"),
        "scans_total": one("SELECT COUNT(*) FROM scan_jobs"),
        "scans_completed": one("SELECT COUNT(*) FROM scan_jobs WHERE status='completed'"),
        "scans_failed": one("SELECT COUNT(*) FROM scan_jobs WHERE status IN ('failed','timeout')"),
        "avg_scan_duration_s": round(one("SELECT COALESCE(AVG(duration_seconds),0) FROM scan_jobs "
                                         "WHERE duration_seconds IS NOT NULL"), 1),
    }


def render(name: str, fmt: str, rows: list[dict], *, title: str = "") -> tuple[bytes, str, str]:
    """Returns (body, media_type, filename)."""
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    filename = f"netwatch-{name}-{stamp}.{fmt}"
    if fmt == "csv":
        buf = io.StringIO()
        if rows:
            writer = csv.DictWriter(buf, fieldnames=list(rows[0].keys()), extrasaction="ignore")
            writer.writeheader()
            for r in rows:
                writer.writerow({k: ("" if v is None else v) for k, v in r.items()})
        return buf.getvalue().encode("utf-8"), "text/csv; charset=utf-8", filename
    if fmt == "json":
        body = json.dumps({"dataset": name, "generated_at": utc_now(), "count": len(rows), "rows": rows},
                          indent=2, default=str)
        return body.encode("utf-8"), "application/json", filename
    if fmt == "html":
        cols = list(rows[0].keys()) if rows else []
        head = "".join(f"<th>{html.escape(c)}</th>" for c in cols)
        body_rows = "".join(
            "<tr>" + "".join(f"<td>{html.escape('' if r.get(c) is None else str(r.get(c)))}</td>" for c in cols)
            + "</tr>" for r in rows)
        page = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<title>{html.escape(title or name)}</title>
<style>body{{font-family:system-ui,sans-serif;margin:24px;color:#111}}table{{border-collapse:collapse;width:100%;font-size:13px}}
th,td{{border:1px solid #ccc;padding:4px 6px;text-align:left;vertical-align:top}}th{{background:#eee}}</style></head>
<body><h1>{html.escape(title or name.title())}</h1><p>Generated {html.escape(utc_now())} · {len(rows)} rows</p>
<table><thead><tr>{head}</tr></thead><tbody>{body_rows}</tbody></table></body></html>"""
        return page.encode("utf-8"), "text/html; charset=utf-8", filename
    raise ValueError(f"unsupported format {fmt}")
