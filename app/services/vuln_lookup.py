"""Version-based lookup of public exploit references (ExploitDB via searchsploit).

This never contacts the target. It reads the service name/product/version that
nmap already recorded and searches a local copy of ExploitDB. A match means
"public exploit material exists for a similar product and version". It does not
mean the device is vulnerable, so findings are stored as unverified.
"""
from __future__ import annotations

import json
import re
import shutil
import sqlite3
import subprocess
from dataclasses import dataclass

from app.database.connection import transaction, utc_now

RULE_KEY = "exploitdb_match"
MAX_LOOKUPS_PER_RUN = 200
MAX_RESULTS_PER_PORT = 5
_SAFE_TERM = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._+\-/]{0,79}$")
_CVE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)


class VulnLookupError(RuntimeError):
    pass


@dataclass
class Match:
    edb_id: str
    title: str
    cves: list[str]
    path: str


def searchsploit_path() -> str | None:
    return shutil.which("searchsploit")


def tool_status() -> dict:
    exe = searchsploit_path()
    return {"searchsploit": {"installed": exe is not None, "path": exe,
                             "install": "sudo apt install exploitdb"},
            "vulners": {"installed": False, "note": "not implemented yet; needs approval"},
            "nuclei": {"installed": shutil.which("nuclei") is not None, "note": "not implemented yet; needs approval"}}


def build_query(product: str, version: str) -> str | None:
    """Return a safe search string or None. Only letters, digits and a few punctuation marks pass."""
    product = (product or "").strip()
    version = (version or "").strip()
    if not product:
        return None
    query = f"{product} {version}".strip() if version else product
    query = re.sub(r"\s+", " ", query)
    if not _SAFE_TERM.match(query):
        return None
    return query


def parse_searchsploit_json(text: str) -> list[Match]:
    try:
        data = json.loads(text or "{}")
    except json.JSONDecodeError as exc:
        raise VulnLookupError(f"unexpected searchsploit output: {exc}") from None
    out: list[Match] = []
    for row in (data.get("RESULTS_EXPLOIT") or [])[:50]:
        codes = row.get("Codes") or ""
        cves = sorted({c.upper() for c in _CVE.findall(codes)})
        out.append(Match(str(row.get("EDB-ID", "")), str(row.get("Title", ""))[:200], cves,
                         str(row.get("Path", ""))[:200]))
    return out


def search(query: str, timeout: float = 20.0) -> list[Match]:
    exe = searchsploit_path()
    if exe is None:
        raise VulnLookupError("searchsploit is not installed (sudo apt install exploitdb)")
    try:
        proc = subprocess.run([exe, "--json", "--", query], capture_output=True, text=True,
                              timeout=timeout, shell=False, check=False)
    except subprocess.TimeoutExpired:
        raise VulnLookupError("searchsploit timed out") from None
    if proc.returncode not in (0, 1):  # searchsploit exits 1 when nothing matches
        raise VulnLookupError(f"searchsploit failed (exit {proc.returncode})")
    return parse_searchsploit_json(proc.stdout)


def check_device(conn: sqlite3.Connection, device_id: int, search_fn=None) -> dict:
    """Look up every open port of a device. Returns counts; writes findings."""
    search_fn = search_fn or search  # resolved at call time so it can be replaced in tests
    rows = conn.execute(
        "SELECT port, protocol, service, product, version FROM open_ports "
        "WHERE device_id = ? AND state = 'open' AND product != ''", (device_id,)).fetchall()
    checked = matched = skipped = 0
    now = utc_now()
    for row in rows:
        if checked >= MAX_LOOKUPS_PER_RUN:
            break
        query = build_query(row["product"], row["version"])
        if query is None:
            skipped += 1
            continue
        checked += 1
        matches = search_fn(query)[:MAX_RESULTS_PER_PORT]
        if not matches:
            _resolve(conn, device_id, row["port"], now)
            continue
        matched += 1
        cves = sorted({c for m in matches for c in m.cves})
        evidence = (f"{row['port']}/{row['protocol']} '{query}': {len(matches)} public exploit reference(s)"
                    f"; ExploitDB IDs {', '.join(m.edb_id for m in matches)}"
                    + (f"; CVEs {', '.join(cves)}" if cves else "; no CVE listed by ExploitDB"))
        _upsert(conn, device_id, row["port"], row["service"], evidence, now)
    return {"device_id": device_id, "ports_checked": checked, "ports_with_references": matched,
            "ports_skipped": skipped}


def _upsert(conn, device_id, port, service, evidence, now):
    title = "Public exploit references for detected version (unverified)"
    description = ("ExploitDB lists public exploit material for a product and version similar to what this "
                   "port reports. The banner can be inaccurate and the device may be patched or not affected. "
                   "Verify the version and the advisory before acting.")
    remediation = ("Confirm the installed version against the vendor advisory. If it is affected, update or "
                   "restrict the service. Do not run exploit code against devices you do not own.")
    with transaction(conn):
        conn.execute(
            """INSERT INTO security_findings(device_id, rule_key, port, title, description, severity, weight,
               service, evidence, remediation, status, first_detected, last_detected)
               VALUES (?,?,?,?,?,'medium',5,?,?,?,'open',?,?)
               ON CONFLICT(device_id, rule_key, port) DO UPDATE SET evidence=excluded.evidence,
               last_detected=excluded.last_detected,
               status = CASE WHEN security_findings.status='resolved' THEN 'open' ELSE security_findings.status END,
               resolved_at = NULL""",
            (device_id, RULE_KEY, port, title, description, service, evidence, remediation, now, now))


def _resolve(conn, device_id, port, now):
    with transaction(conn):
        conn.execute(
            "UPDATE security_findings SET status='resolved', resolved_at=? "
            "WHERE device_id=? AND rule_key=? AND port=? AND status!='resolved'",
            (now, device_id, RULE_KEY, port))
