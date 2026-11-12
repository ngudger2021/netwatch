"""Vulnerability checks that do contact devices (version lookup via nmap vulners, HTTP exposure checks via Nuclei).

Safety rules enforced here, not left to the caller:
  * both tools are disabled unless enabled in [vulnerability] config
  * every argument list is fixed; the only variable parts are validated IPs, ports and URLs
  * only devices on configured networks, and only ports already observed open
  * vulners: the single NSE script 'vulners' (no wildcards, no other scripts)
  * Nuclei: an allow-list of template tags; dos, fuzz, intrusive, brute-force and default-login are excluded;
    rate and concurrency are low; out-of-band (interactsh) callbacks are disabled
Findings are labelled as unverified: they say what a tool reported, not that the device is exploitable.
"""
from __future__ import annotations

import ipaddress
import json
import re
import shutil
import sqlite3
import subprocess
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from app.config import Settings
from app.database.connection import transaction, utc_now
from app.scanners import nmap_parser
from app.scanners.nmap_runner import build_command, run_command
from app.scanners.targets import normalise_ports
from app.services.audit import SEVERITY_ORDER

VULNERS_RULE = "vulners_cve"
NUCLEI_RULE = "nuclei_match"
NUCLEI_TAGS = "exposure,misconfig,tech,panel"
NUCLEI_EXCLUDE_TAGS = "dos,fuzz,intrusive,brute-force,bruteforce,default-login,sqli,xss,rce,lfi,ssrf"
WEB_SERVICES = {"http", "https", "http-proxy", "http-alt", "ssl/http", "ssl/https", "https-alt"}
_CVE = re.compile(r"(CVE-\d{4}-\d{4,})\s+(\d{1,2}(?:\.\d)?)", re.I)
_NUCLEI_SEVERITIES = ("info", "low", "medium", "high", "critical")


class VulnToolError(RuntimeError):
    pass


# ---------- tool availability ---------------------------------------------
def nuclei_path() -> str | None:
    return shutil.which("nuclei")


def vulners_script_installed(nmap_path: str) -> bool:
    try:
        proc = subprocess.run([nmap_path, "--script-help", "vulners"], capture_output=True, text=True,
                              timeout=30, shell=False, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return proc.returncode == 0 and "vulners" in proc.stdout


def status(settings: Settings) -> dict:
    cfg = settings.vulnerability
    vulners_ok = vulners_script_installed(settings.scanning.nmap_path)
    nuclei_ok = nuclei_path() is not None
    return {
        "vulners": {"enabled": cfg.vulners_enabled, "installed": vulners_ok,
                    "sends_data_to": "vulners.com (service names and versions)",
                    "install": "see README 'Vulnerability checks'"},
        "nuclei": {"enabled": cfg.nuclei_enabled, "installed": nuclei_ok,
                   "tags": NUCLEI_TAGS, "excluded_tags": NUCLEI_EXCLUDE_TAGS,
                   "install": "sudo apt install nuclei && nuclei -update-templates"},
    }


# ---------- vulners ---------------------------------------------------------
def build_vulners_args(ip: str, ports: str, outfile: str, host_timeout: int = 600) -> list[str]:
    addr = str(ipaddress.ip_address(ip))  # raises on anything that is not an IP literal
    spec = normalise_ports(ports)
    if not spec:
        raise ValueError("vulners needs at least one port")
    return ["-sT", "-sV", "--version-light", "--script", "vulners", "-p", spec,
            "--max-retries", "1", "--host-timeout", f"{host_timeout}s", "--unprivileged",
            "-oX", outfile, "--", addr]


def parse_vulners_output(output: str) -> list[tuple[str, float]]:
    """Return (CVE id, CVSS score) pairs found in the vulners script output, highest first, deduplicated."""
    best: dict[str, float] = {}
    for cve, score in _CVE.findall(output or ""):
        cve = cve.upper()
        best[cve] = max(best.get(cve, 0.0), float(score))
    return sorted(best.items(), key=lambda kv: (-kv[1], kv[0]))


def cvss_severity(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


WEIGHTS = {"critical": 20, "high": 12, "medium": 5, "low": 2, "info": 0}


def store_finding(conn: sqlite3.Connection, device_id: int, rule_key: str, port: int, service: str, *,
                  title: str, description: str, severity: str, evidence: str, remediation: str) -> None:
    now = utc_now()
    with transaction(conn):
        conn.execute(
            """INSERT INTO security_findings(device_id, rule_key, port, title, description, severity, weight,
               service, evidence, remediation, status, first_detected, last_detected)
               VALUES (?,?,?,?,?,?,?,?,?,?,'open',?,?)
               ON CONFLICT(device_id, rule_key, port) DO UPDATE SET severity=excluded.severity,
               weight=excluded.weight, evidence=excluded.evidence, title=excluded.title,
               last_detected=excluded.last_detected,
               status = CASE WHEN security_findings.status='resolved' THEN 'open' ELSE security_findings.status END,
               resolved_at = NULL""",
            (device_id, rule_key, port, title, description, severity, WEIGHTS.get(severity, 0), service,
             evidence[:2000], remediation, now, now))


def resolve_missing(conn: sqlite3.Connection, device_id: int, rule_key: str, keep_ports: set[int]) -> None:
    now = utc_now()
    with transaction(conn):
        rows = conn.execute("SELECT id, port FROM security_findings WHERE device_id=? AND rule_key=? "
                            "AND status!='resolved'", (device_id, rule_key)).fetchall()
        for row in rows:
            if row["port"] not in keep_ports:
                conn.execute("UPDATE security_findings SET status='resolved', resolved_at=? WHERE id=?",
                             (now, row["id"]))


def store_vulners(conn, device_id: int, port: int, service: str, cves: list[tuple[str, float]]) -> None:
    top_sev = cvss_severity(cves[0][1])
    evidence = "; ".join(f"{c} (CVSS {s})" for c, s in cves[:10])
    store_finding(
        conn, device_id, VULNERS_RULE, port, service,
        title="Known CVEs listed for detected version (unverified)",
        description=("The vulners database lists CVEs for the product and version this port reports. "
                     "Version banners can be wrong or patched backports can exist, so each CVE needs checking."),
        severity=top_sev, evidence=f"{port}/tcp: {evidence}",
        remediation="Check each CVE against the vendor advisory for your exact build. Update or restrict the service if affected.")


# ---------- nuclei ----------------------------------------------------------
def build_nuclei_args(targets_file: str, outfile: str, templates_dir: str = "") -> list[str]:
    args = ["-l", targets_file, "-jsonl", "-o", outfile, "-silent", "-duc", "-ni",
            "-tags", NUCLEI_TAGS, "-exclude-tags", NUCLEI_EXCLUDE_TAGS,
            "-rl", "5", "-c", "3", "-timeout", "5", "-retries", "0", "-no-color"]
    if templates_dir:
        args += ["-t", templates_dir]
    return args


def build_urls(ip: str, port: int, service: str, product: str) -> str | None:
    if port <= 0 or port > 65535:
        return None
    if service not in WEB_SERVICES and "http" not in (product or "").lower():
        return None
    scheme = "https" if ("ssl" in service or "https" in service or port in (443, 8443)) else "http"
    return f"{scheme}://{ip}:{port}/"


def parse_nuclei_jsonl(text: str) -> list[dict]:
    hits = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = item.get("info") or {}
        sev = str(info.get("severity", "info")).lower()
        if sev not in _NUCLEI_SEVERITIES:
            sev = "info"
        hits.append({"template": str(item.get("template-id", ""))[:120],
                     "name": str(info.get("name", ""))[:200], "severity": sev,
                     "matched_at": str(item.get("matched-at", ""))[:300]})
    return hits


def worst(severities: list[str]) -> str:
    return max(severities, key=lambda s: SEVERITY_ORDER.get(s, 0), default="info")


# ---------- orchestration ---------------------------------------------------
@dataclass
class DeviceSpec:
    device_id: int
    ip: str
    ports: list[sqlite3.Row]


def load_devices(conn: sqlite3.Connection, device_ids: list[int] | None) -> list[DeviceSpec]:
    where = "AND d.id IN (%s)" % ",".join("?" * len(device_ids)) if device_ids else ""
    rows = conn.execute(
        f"""SELECT d.id, d.current_ip, p.port, p.protocol, p.service, p.product, p.version
            FROM devices d JOIN open_ports p ON p.device_id = d.id
            WHERE p.state='open' AND p.protocol='tcp' AND d.current_ip != '' {where}
            ORDER BY d.id, p.port""", device_ids or []).fetchall()
    specs: dict[int, DeviceSpec] = {}
    for r in rows:
        spec = specs.setdefault(r["id"], DeviceSpec(r["id"], r["current_ip"], []))
        spec.ports.append(r)
    return list(specs.values())


def run_vulners(conn, settings: Settings, specs: list[DeviceSpec], scans_dir: Path) -> dict:
    checked = findings = 0
    for spec in specs:
        ports = [p["port"] for p in spec.ports][: settings.vulnerability.max_ports_per_device]
        out = scans_dir / f"vulners-{spec.device_id}.xml"
        err = scans_dir / f"vulners-{spec.device_id}.err"
        argv = build_vulners_args(spec.ip, ",".join(map(str, ports)), str(out))
        res = run_command(build_command(settings.scanning, argv),
                          timeout=settings.vulnerability.timeout_seconds, stderr_path=str(err))
        try:
            if not res.ok:
                raise VulnToolError(f"nmap vulners failed for {spec.ip}")
            report = nmap_parser.parse_nmap_xml(out.read_text(encoding="utf-8", errors="replace"), ports_scanned=True)
        except (VulnToolError, OSError, nmap_parser.NmapParseError):
            continue
        finally:
            out.unlink(missing_ok=True)
        checked += 1
        kept: set[int] = set()
        for host in report.hosts:
            for port in host.ports:
                output = port.scripts.get("vulners", "")
                cves = parse_vulners_output(output)
                if not cves:
                    continue
                kept.add(port.port)
                store_vulners(conn, spec.device_id, port.port, port.service, cves)
                findings += 1
        resolve_missing(conn, spec.device_id, VULNERS_RULE, kept)
    return {"devices_checked": checked, "ports_with_cves": findings}


def run_nuclei(conn, settings: Settings, specs: list[DeviceSpec], scans_dir: Path, binary: str) -> dict:
    urls: dict[str, tuple[int, int]] = {}
    for spec in specs:
        for p in spec.ports:
            url = build_urls(spec.ip, p["port"], p["service"], p["product"])
            if url:
                urls[url] = (spec.device_id, p["port"])
            if len(urls) >= settings.vulnerability.max_urls:
                break
    if not urls:
        return {"urls": 0, "matches": 0}
    targets = scans_dir / "nuclei-targets.txt"
    targets.write_text("\n".join(urls) + "\n", encoding="utf-8")
    out = scans_dir / "nuclei-out.jsonl"
    err = scans_dir / "nuclei.err"
    cmd = [binary, *build_nuclei_args(str(targets), str(out), settings.vulnerability.nuclei_templates_dir)]
    res = run_command(cmd, timeout=settings.vulnerability.timeout_seconds, stderr_path=str(err))
    try:
        if not res.ok and not out.exists():
            raise VulnToolError(f"nuclei failed: {res.stderr_tail.strip().splitlines()[-1:] or ['unknown']}")
        hits = parse_nuclei_jsonl(out.read_text(encoding="utf-8", errors="replace") if out.exists() else "")
    finally:
        targets.unlink(missing_ok=True)
        out.unlink(missing_ok=True)
    # Match by (host, port) of the parsed URL, never by string prefix (port 80 must not match 8080).
    by_endpoint: dict[tuple[str, int], tuple[int, int]] = {}
    for url, ident in urls.items():
        parts = urlsplit(url)
        by_endpoint[(parts.hostname or "", parts.port or 0)] = ident
    by_port: dict[tuple[int, int], list[dict]] = {}
    for h in hits:
        try:
            parts = urlsplit(h["matched_at"])
            key = by_endpoint.get((parts.hostname or "", parts.port or 0))
        except ValueError:
            key = None
        if key is None:
            continue
        by_port.setdefault(key, []).append(h)
    seen_by_device: dict[int, set[int]] = {}
    for (device_id, port), items in by_port.items():
        sev = worst([i["severity"] for i in items])
        names = "; ".join(f"{i['template']} ({i['severity']})" for i in items[:10])
        store_finding(
            conn, device_id, NUCLEI_RULE, port, "",
            title="Web exposure or misconfiguration reported by Nuclei (unverified)",
            description=("Nuclei matched exposure, misconfiguration or technology templates on this web port. "
                         "Each match needs a manual check before it counts as a real problem."),
            severity=sev, evidence=f"{port}/tcp: {names}",
            remediation="Open the matched URL yourself, confirm what is exposed, then fix or restrict it.")
        seen_by_device.setdefault(device_id, set()).add(port)
    for spec in specs:
        resolve_missing(conn, spec.device_id, NUCLEI_RULE, seen_by_device.get(spec.device_id, set()))
    return {"urls": len(urls), "matches": len(hits)}
