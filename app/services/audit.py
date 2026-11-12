"""Non-intrusive security auditing.

Findings are derived ONLY from observed evidence: open ports, service names,
and banner/version strings nmap collected during a normal -sV scan. No
exploitation, no credential attempts, no NSE scripts beyond what the operator
configured. A port being open is NOT by itself a vulnerability; SSH, for
example, is recorded as informational only.

Risk score (0-100) = min(100, sum of weights of currently open findings).
Trusted devices keep the same score and findings: trust never hides a finding.
"""
from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field

from app.database.connection import utc_now

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass(frozen=True)
class Rule:
    key: str
    title: str
    severity: str
    weight: int
    description: str
    remediation: str
    ports: frozenset[int] = frozenset()
    services: frozenset[str] = frozenset()
    require_plain_http: bool = False
    require_script: str = ""          # NSE script id whose output must mention `script_match`
    script_match: str = ""


RULES: tuple[Rule, ...] = (
    Rule("telnet", "Telnet service exposed", "high", 25,
         "Telnet transmits credentials and session data in cleartext.",
         "Disable Telnet and use SSH instead. If the device has no SSH option, restrict access by firewall to a management VLAN.",
         ports=frozenset({23}), services=frozenset({"telnet"})),
    Rule("ftp_plain", "Unencrypted FTP service", "medium", 10,
         "FTP sends credentials and files in cleartext.",
         "Replace with SFTP/FTPS, or disable the service if unused.",
         ports=frozenset({21}), services=frozenset({"ftp"})),
    Rule("http_plain_mgmt", "Unencrypted HTTP management interface", "low", 4,
         "A web interface is served over plain HTTP, so logins are visible to anyone on the path.",
         "Enable HTTPS on the device, or restrict the interface to trusted addresses.",
         ports=frozenset({80, 8000, 8008, 8080, 8888}), services=frozenset({"http"}), require_plain_http=True),
    Rule("smbv1", "SMBv1 positively identified", "high", 25,
         "The SMB script output reports SMBv1 is enabled. SMBv1 is obsolete and exploitable.",
         "Disable SMBv1 (Windows: Disable-WindowsOptionalFeature SMB1Protocol) and keep SMBv2/v3 only.",
         ports=frozenset({445, 139}), require_script="smb-protocols", script_match="SMBv1"),
    Rule("db_exposed", "Database service reachable on LAN", "high", 20,
         "A database listener is reachable from the network. Databases should normally be bound to localhost or an app subnet.",
         "Bind the database to localhost or a dedicated interface, require authentication, and firewall the port.",
         ports=frozenset({1433, 3306, 5432, 5984, 6379, 9200, 11211, 27017}),
         services=frozenset({"mysql", "postgresql", "ms-sql-s", "mongodb", "redis", "elasticsearch", "memcache", "couchdb"})),
    Rule("rdp_exposed", "Remote Desktop (RDP) reachable", "medium", 10,
         "RDP is a common target for credential attacks.",
         "Restrict RDP to a VPN or admin subnet and enable Network Level Authentication.",
         ports=frozenset({3389}), services=frozenset({"ms-wbt-server"})),
    Rule("vnc_exposed", "VNC remote desktop reachable", "high", 20,
         "VNC services are frequently configured without strong authentication or encryption.",
         "Tunnel VNC over SSH or VPN only, and require strong passwords.",
         ports=frozenset({5900, 5901}), services=frozenset({"vnc"})),
    Rule("winrm_exposed", "WinRM management reachable", "medium", 8,
         "Windows Remote Management is reachable on the LAN.",
         "Limit WinRM to administrative hosts through firewall rules.",
         ports=frozenset({5985, 5986}), services=frozenset({"wsman", "wsmans"})),
    Rule("ipmi_exposed", "IPMI / out-of-band management reachable", "medium", 10,
         "IPMI/BMC interfaces have historically weak authentication.",
         "Place the BMC on a dedicated management network and update its firmware.",
         ports=frozenset({623}), services=frozenset({"asf-rmcp"})),
    Rule("ssh_info", "SSH service reachable", "info", 0,
         "SSH is present. This is informational only and not a vulnerability by itself.",
         "No action needed if key-based authentication is used. Review who can reach it.",
         ports=frozenset({22}), services=frozenset({"ssh"})),
)


@dataclass
class Finding:
    rule_key: str
    port: int
    title: str
    description: str
    severity: str
    weight: int
    service: str
    evidence: str
    remediation: str


@dataclass
class Evaluation:
    device_id: int
    findings: list[Finding] = field(default_factory=list)
    score: int = 0
    explanation: list[dict] = field(default_factory=list)


def _matches(rule: Rule, port: sqlite3.Row, device_type: str) -> bool:
    if rule.require_script:
        script = port["script_output"] or ""
        return rule.require_script in script and rule.script_match in script
    if rule.require_plain_http:
        return (port["port"] in rule.ports or port["service"] in rule.services) and \
            port["service"] != "https" and "ssl" not in (port["extrainfo"] or "").lower()
    return port["port"] in rule.ports or port["service"] in rule.services


def evaluate_open_ports(device_id: int, device_type: str, open_ports: list[sqlite3.Row]) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[tuple[str, int]] = set()
    for port in open_ports:
        for rule in RULES:
            if not _matches(rule, port, device_type):
                continue
            key = (rule.key, port["port"])
            if key in seen:
                continue
            seen.add(key)
            evidence = (
                f"{port['port']}/{port['protocol']} open; service='{port['service'] or 'unknown'}'; "
                f"banner='{(port['product'] + ' ' + port['version']).strip() or 'n/a'}'"
            )
            if rule.require_script:
                evidence += f"; script {rule.require_script} matched '{rule.script_match}'"
            findings.append(Finding(rule.key, port["port"], rule.title, rule.description,
                                    rule.severity, rule.weight, port["service"], evidence,
                                    rule.remediation))
    return findings


def compute_score(findings: list[Finding]) -> tuple[int, list[dict]]:
    explanation = [{"rule": f.rule_key, "title": f.title, "port": f.port, "weight": f.weight}
                   for f in findings if f.weight > 0]
    return min(100, sum(f.weight for f in findings)), explanation


def sync_device_findings(conn: sqlite3.Connection, device_id: int, device_type: str, now: str | None = None) -> list[dict]:
    """Reconcile stored findings with current evidence. Returns change events to record."""
    now = now or utc_now()
    open_rows = conn.execute(
        "SELECT * FROM open_ports WHERE device_id = ? AND state = 'open'", (device_id,)
    ).fetchall()
    current = evaluate_open_ports(device_id, device_type, open_rows)
    score, explanation = compute_score(current)
    events: list[dict] = []
    current_keys = {(f.rule_key, f.port) for f in current}

    existing = {(r["rule_key"], r["port"]): r for r in conn.execute(
        "SELECT * FROM security_findings WHERE device_id = ?", (device_id,))}

    for f in current:
        row = existing.get((f.rule_key, f.port))
        if row is None:
            conn.execute(
                """INSERT INTO security_findings
                   (device_id, rule_key, port, title, description, severity, weight, service,
                    evidence, remediation, status, first_detected, last_detected)
                   VALUES (?,?,?,?,?,?,?,?,?,?,'open',?,?)""",
                (device_id, f.rule_key, f.port, f.title, f.description, f.severity, f.weight,
                 f.service, f.evidence, f.remediation, now, now))
            if f.severity != "info":
                events.append({"type": "finding_new", "severity": f.severity,
                               "title": f"New finding: {f.title} (port {f.port})",
                               "device_id": device_id,
                               "details": {"rule": f.rule_key, "port": f.port, "evidence": f.evidence}})
        else:
            reopened = row["status"] == "resolved"
            conn.execute(
                """UPDATE security_findings SET last_detected=?, evidence=?, severity=?, weight=?,
                   status = CASE WHEN status='resolved' THEN 'open' ELSE status END,
                   resolved_at = NULL WHERE id=?""",
                (now, f.evidence, f.severity, f.weight, row["id"]))
            if reopened and f.severity != "info":
                events.append({"type": "finding_new", "severity": f.severity,
                               "title": f"Finding reappeared: {f.title} (port {f.port})",
                               "device_id": device_id,
                               "details": {"rule": f.rule_key, "port": f.port}})

    builtin_rules = {r.key for r in RULES}
    for key, row in existing.items():
        # Only findings produced by the built-in rules are resolved here. Findings from other
        # checks (e.g. exploitdb_match) are managed by their own check and must survive a sync.
        if row["rule_key"] not in builtin_rules:
            continue
        if key not in current_keys and row["status"] != "resolved":
            conn.execute("UPDATE security_findings SET status='resolved', resolved_at=? WHERE id=?",
                         (now, row["id"]))
            events.append({"type": "finding_resolved", "severity": "info",
                           "title": f"Finding resolved: {row['title']} (port {row['port']})",
                           "device_id": device_id, "details": {"rule": row["rule_key"]}})

    conn.execute("UPDATE devices SET risk_score = ? WHERE id = ?", (score, device_id))
    return events


def severity_at_least(value: str, minimum: str) -> bool:
    return SEVERITY_ORDER.get(value, 0) >= SEVERITY_ORDER.get(minimum, 0)


def risk_level(score: int) -> str:
    if score >= 60:
        return "high"
    if score >= 25:
        return "medium"
    return "low"


def explain_json(explanation: list[dict]) -> str:
    return json.dumps(explanation)
