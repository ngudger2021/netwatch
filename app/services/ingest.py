"""Persist scan results and detect changes against previous observations.

One call handles one *unit* of scanning (a whole network, or a narrower custom
target). Everything for a unit is written in a single IMMEDIATE transaction, so
an interruption leaves either the previous state or the complete new state.

Absence handling is only applied when the unit covered the entire network and
the scan succeeded. A failed or cancelled scan never increments missing counts,
which is how scan failure is kept distinct from a device disappearing.
"""
from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field

from app.database.connection import transaction
from app.models import HostResult, PortResult, ScanReport
from app.scanners.neighbors import is_randomized_mac, vendor_for_mac
from app.services.audit import RULES, sync_device_findings
from app.services.classify import classify_device
from app.services.identity import Observation, normalise_mac, resolve_device

# Ports whose appearance is noteworthy enough to raise the event severity.
RISKY_PORTS: frozenset[int] = frozenset().union(*(r.ports for r in RULES if r.weight >= 8))


@dataclass(frozen=True)
class PortScope:
    mode: str                     # 'top' (default port list), 'explicit' (port spec), 'none' (no port scan)
    ports: frozenset[int] = frozenset()

    def eligible_for_close(self, row: sqlite3.Row) -> bool:
        if self.mode == "top":
            return row["scope"] == "top"
        if self.mode == "explicit":
            return row["port"] in self.ports
        return False


@dataclass
class UnitResult:
    hosts_up: int = 0
    new_devices: int = 0
    events: list[dict] = field(default_factory=list)


def _event(type_: str, severity: str, title: str, device_id: int | None, job_id: int | None,
           details: dict | None = None) -> dict:
    return {"type": type_, "severity": severity, "title": title, "device_id": device_id,
            "job_id": job_id, "details": details or {}}


def _store_events(conn: sqlite3.Connection, events: list[dict], now: str) -> None:
    for ev in events:
        ev.setdefault("job_id", None)
        cur = conn.execute(
            "INSERT INTO events(created_at, type, severity, device_id, job_id, title, details) "
            "VALUES (?,?,?,?,?,?,?)",
            (now, ev["type"], ev["severity"], ev.get("device_id"), ev.get("job_id"),
             ev["title"], json.dumps(ev.get("details", {}), default=str)))
        ev["id"] = cur.lastrowid
        ev["created_at"] = now


def ingest_unit(
    conn: sqlite3.Connection,
    *,
    job_id: int,
    network_id: int | None,
    report: ScanReport,
    observed_at: str,
    ports: PortScope,
    absence_check: bool,
    offline_threshold: int = 3,
    recent_days: int = 7,
    local_macs: dict[str, str] | None = None,
    oui_file: str = "",
) -> UnitResult:
    result = UnitResult(hosts_up=len(report.hosts))
    events: list[dict] = []
    seen: set[int] = set()
    with transaction(conn):
        for host in report.hosts:
            mac = normalise_mac(host.mac)
            if mac is None and local_macs and host.ip in local_macs:
                mac = normalise_mac(local_macs[host.ip])   # neighbour table: local subnets only
            obs = Observation(ip=host.ip, network_id=network_id, observed_at=observed_at,
                              mac=mac, hostname=host.hostname or "", vendor=host.vendor or "")
            res = resolve_device(conn, obs, seen, recent_days=recent_days)
            device_id, host_events, created = _apply_host(
                conn, job_id, res, host, obs, mac, observed_at, ports, oui_file)
            seen.add(device_id)
            events += host_events
            result.new_devices += int(created)

        if absence_check and network_id is not None:
            events += _apply_absence(conn, job_id, network_id, seen, observed_at, offline_threshold)

        _store_events(conn, events, observed_at)
    result.events = events
    return result


def _apply_host(conn, job_id, res, host: HostResult, obs: Observation, mac: str | None,
                now: str, ports: PortScope, oui_file: str) -> tuple[int, list[dict], bool]:
    events: list[dict] = []
    vendor = obs.vendor or vendor_for_mac(mac, oui_file)
    randomized = int(bool(mac and is_randomized_mac(mac)))

    if res.created:
        cur = conn.execute(
            """INSERT INTO devices(mac, mac_randomized, hostname, vendor, device_type, network_id,
               current_ip, status, missing_scans, first_seen, last_seen, created_at, updated_at)
               VALUES (?,?,?,?,?,?,?,'online',0,?,?,?,?)""",
            (mac, randomized, obs.hostname, vendor, "unknown", obs.network_id, host.ip,
             now, now, now, now))
        device_id = cur.lastrowid
        label = obs.hostname or vendor or mac or "unidentified host"
        events.append(_event("device_new", "low", f"New device {host.ip} ({label})", device_id, job_id,
                             {"ip": host.ip, "mac": mac, "vendor": vendor, "hostname": obs.hostname}))
        created = True
    else:
        device_id = res.device_id
        old = conn.execute("SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone()
        label = old["custom_name"] or old["hostname"] or old["vendor"] or host.ip
        if old["status"] != "online":
            events.append(_event("device_returned", "info", f"Device back online: {label} ({host.ip})",
                                 device_id, job_id, {"ip": host.ip, "previous_status": old["status"]}))
        if res.reason in ("heuristic", "ip-anchored"):
            events.append(_event("device_identity_merged", "info",
                                 f"Identity matched by {res.reason} (score {res.score}): {host.ip}",
                                 device_id, job_id,
                                 {"reason": res.reason, "score": res.score, "new_mac": mac, "old_mac": old["mac"]}))
        if old["current_ip"] and old["current_ip"] != host.ip:
            events.append(_event("ip_changed", "info", f"IP changed for {label}: {old['current_ip']} -> {host.ip}",
                                 device_id, job_id, {"old_ip": old["current_ip"], "new_ip": host.ip}))
        if obs.hostname and obs.hostname != old["hostname"]:
            if old["hostname"]:
                events.append(_event("hostname_changed", "info",
                                     f"Hostname changed for {host.ip}: {old['hostname']} -> {obs.hostname}",
                                     device_id, job_id, {"old": old["hostname"], "new": obs.hostname}))
        updates = {
            "status": "online", "missing_scans": 0, "last_seen": now, "updated_at": now,
            "current_ip": host.ip, "network_id": obs.network_id,
            "hostname": obs.hostname or old["hostname"],
            "vendor": vendor or old["vendor"],
        }
        if mac and mac != old["mac"]:
            if old["mac"] and res.reason == "heuristic":
                events.append(_event("mac_changed", "info", f"MAC changed for {label}",
                                     device_id, job_id, {"old": old["mac"], "new": mac}))
            updates["mac"] = mac
            updates["mac_randomized"] = randomized
        assignments = ", ".join(f"{k} = ?" for k in updates)
        conn.execute(f"UPDATE devices SET {assignments} WHERE id = ?", (*updates.values(), device_id))
        created = False

    conn.execute(
        """INSERT INTO device_addresses(device_id, ip, network_id, first_seen, last_seen)
           VALUES (?,?,?,?,?)
           ON CONFLICT(device_id, ip) DO UPDATE SET last_seen = excluded.last_seen,
                                                    network_id = excluded.network_id""",
        (device_id, host.ip, obs.network_id, now, now))
    conn.execute(
        """INSERT INTO scan_results(job_id, device_id, ip, mac, hostname, vendor, ports_scanned, observed_at)
           VALUES (?,?,?,?,?,?,?,?)""",
        (job_id, device_id, host.ip, mac, obs.hostname, vendor, int(host.ports_scanned), now))
    conn.execute(
        "INSERT INTO device_observations(device_id, job_id, ip, status, observed_at) VALUES (?,?,?, 'online', ?)",
        (device_id, job_id, host.ip, now))

    if host.ports_scanned:
        events += _sync_ports(conn, device_id, host, job_id, now, ports, label)

    dev = conn.execute("SELECT device_type_source, device_type FROM devices WHERE id = ?", (device_id,)).fetchone()
    if dev["device_type_source"] == "auto":
        open_ports = {p.port for p in host.ports if p.state == "open"}
        product_text = " ".join(f"{p.product} {p.extrainfo}" for p in host.ports if p.state == "open")
        kind = classify_device(host.ip, vendor, obs.hostname, open_ports, product_text)
        if kind != dev["device_type"]:
            conn.execute("UPDATE devices SET device_type = ? WHERE id = ?", (kind, device_id))

    events += _sync_findings(conn, device_id, job_id, now)
    return device_id, events, created


def _sync_ports(conn, device_id: int, host: HostResult, job_id: int, now: str,
                scope: PortScope, label: str) -> list[dict]:
    events: list[dict] = []
    observed: dict[tuple[int, str], PortResult] = {
        (p.port, p.protocol): p for p in host.ports if p.state == "open"}
    existing = {(r["port"], r["protocol"]): r for r in conn.execute(
        "SELECT * FROM open_ports WHERE device_id = ?", (device_id,))}
    new_scope = "top" if scope.mode == "top" else "explicit"

    for key, p in observed.items():
        script = "; ".join(f"{k}: {v}" for k, v in p.scripts.items())[:1000]
        row = existing.get(key)
        if row is None:
            conn.execute(
                """INSERT INTO open_ports(device_id, port, protocol, state, service, product, version,
                   extrainfo, script_output, scope, first_seen, last_seen)
                   VALUES (?,?,?,'open',?,?,?,?,?,?,?,?)""",
                (device_id, p.port, p.protocol, p.service, p.product, p.version, p.extrainfo,
                 script, new_scope, now, now))
            sev = "medium" if p.port in RISKY_PORTS else "info"
            events.append(_event("port_opened", sev,
                                 f"Port {p.port}/{p.protocol} opened on {label} ({p.service or 'unknown'})",
                                 device_id, job_id, {"port": p.port, "service": p.service}))
        else:
            if row["state"] == "closed":
                events.append(_event("port_reopened", "info",
                                     f"Port {p.port}/{p.protocol} reopened on {label}",
                                     device_id, job_id, {"port": p.port}))
            prev_name = (row["service"], row["product"], row["version"])
            new_name = (p.service, p.product, p.version)
            if prev_name != new_name and (row["product"] or row["version"]) and (p.product or p.version):
                events.append(_event("service_changed", "low",
                                     f"Service changed on {label} port {p.port}: "
                                     f"{' '.join(filter(None, prev_name))} -> {' '.join(filter(None, new_name))}",
                                     device_id, job_id, {"port": p.port, "old": prev_name, "new": new_name}))
            conn.execute(
                """UPDATE open_ports SET state='open', closed_at=NULL, last_seen=?, service=?, product=?,
                   version=?, extrainfo=?, script_output=? WHERE id=?""",
                (now, p.service, p.product, p.version, p.extrainfo, script, row["id"]))
        conn.execute(
            """INSERT INTO service_observations(device_id, job_id, port, protocol, service, product, version, observed_at)
               VALUES (?,?,?,?,?,?,?,?)""",
            (device_id, job_id, p.port, p.protocol, p.service, p.product, p.version, now))

    for key, row in existing.items():
        if key in observed or row["state"] != "open":
            continue
        if not scope.eligible_for_close(row):
            continue  # not covered by this scan's port set: cannot conclude it closed
        conn.execute("UPDATE open_ports SET state='closed', closed_at=? WHERE id=?", (now, row["id"]))
        events.append(_event("port_closed", "info",
                             f"Port {row['port']}/{row['protocol']} closed on {label}",
                             device_id, job_id, {"port": row["port"], "service": row["service"]}))
    return events


def _sync_findings(conn, device_id: int, job_id: int, now: str) -> list[dict]:
    dev = conn.execute("SELECT device_type, trusted FROM devices WHERE id = ?", (device_id,)).fetchone()
    raw = sync_device_findings(conn, device_id, dev["device_type"], now)
    events = []
    for ev in raw:
        events.append(_event(ev["type"], ev["severity"], ev["title"], device_id, job_id, ev.get("details")))
    return events


def _apply_absence(conn, job_id: int, network_id: int, seen: set[int], now: str,
                   threshold: int) -> list[dict]:
    events: list[dict] = []
    rows = conn.execute(
        "SELECT id, status, missing_scans, custom_name, hostname, current_ip, last_seen "
        "FROM devices WHERE network_id = ?", (network_id,)).fetchall()
    for row in rows:
        if row["id"] in seen:
            continue
        missing = min(row["missing_scans"] + 1, 10_000)
        new_status = row["status"]
        label = row["custom_name"] or row["hostname"] or row["current_ip"]
        if row["status"] == "online" and missing >= threshold:
            new_status = "offline"
            events.append(_event("device_offline", "medium",
                                 f"Device offline: {label} ({row['current_ip']})",
                                 row["id"], job_id,
                                 {"missing_scans": missing, "last_seen": row["last_seen"]}))
        elif row["status"] == "unknown" and missing >= threshold:
            new_status = "offline"
        conn.execute("UPDATE devices SET missing_scans = ?, status = ?, updated_at = ? WHERE id = ?",
                     (missing, new_status, now, row["id"]))
        conn.execute(
            "INSERT INTO device_observations(device_id, job_id, ip, status, observed_at) VALUES (?,?,?, 'absent', ?)",
            (row["id"], job_id, row["current_ip"], now))
    return events
