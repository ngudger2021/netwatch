"""Device identity resolution.

Rules, in order:

1. A real (non-randomised) MAC address is authoritative. If a device already
   has that MAC it is the same device, full stop.
2. Two devices with different real MACs are NEVER merged, whatever else matches.
3. Otherwise the observation is compared with candidate devices that have no
   MAC or a randomised MAC and were not already matched in this scan. Each
   candidate gets a score from corroborating evidence:

       same IP on the same network     +50
       same hostname (case-insensitive) +40
       same vendor string              +15
       seen within `recent_days`       +15

   A heuristic merge requires a score >= MERGE_THRESHOLD (70). A shared
   hostname or IP alone is therefore never enough (hostname + network = 60).
4. An observation with no MAC at all may match a MAC-less device at the same
   IP on the same network (score 50 -> accepted only in this IP-anchored case).

Anything else creates a new device record. Merges are reported as events so the
operator can audit them.
"""
from __future__ import annotations

import re
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from app.database.connection import parse_ts
from app.scanners.neighbors import is_randomized_mac

MERGE_THRESHOLD = 70
IP_ANCHOR_THRESHOLD = 50
_MAC_RE = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")


@dataclass
class Observation:
    ip: str
    network_id: int | None
    observed_at: str
    mac: str | None = None
    hostname: str = ""
    vendor: str = ""


@dataclass
class Resolution:
    device_id: int
    created: bool
    reason: str       # 'mac' | 'created' | 'heuristic' | 'ip-anchored'
    score: int = 0


def normalise_mac(mac: str | None) -> str | None:
    if not mac:
        return None
    value = mac.strip().lower().replace("-", ":")
    return value if _MAC_RE.match(value) else None


def _recent(last_seen: str | None, observed_at: str, days: int) -> bool:
    last = parse_ts(last_seen)
    now = parse_ts(observed_at) or datetime.now(timezone.utc)
    return last is not None and now - last <= timedelta(days=days)


def score_candidate(cand: sqlite3.Row, obs: Observation, recent_days: int) -> int:
    score = 0
    if cand["current_ip"] and cand["current_ip"] == obs.ip and cand["network_id"] == obs.network_id:
        score += 50
    if obs.hostname and cand["hostname"] and obs.hostname.lower() == cand["hostname"].lower():
        score += 40
    if obs.vendor and cand["vendor"] and obs.vendor.lower() == cand["vendor"].lower():
        score += 15
    if _recent(cand["last_seen"], obs.observed_at, recent_days):
        score += 15
    return score


def resolve_device(
    conn: sqlite3.Connection,
    obs: Observation,
    seen_in_scan: set[int],
    recent_days: int = 7,
) -> Resolution:
    mac = normalise_mac(obs.mac)

    if mac and not is_randomized_mac(mac):
        row = conn.execute("SELECT id FROM devices WHERE mac = ?", (mac,)).fetchone()
        if row:
            return Resolution(row["id"], False, "mac", 100)

    # Candidates: devices without a stable identity on this network.
    candidates = conn.execute(
        """SELECT * FROM devices
           WHERE network_id IS ? AND (mac IS NULL OR mac_randomized = 1)""",
        (obs.network_id,),
    ).fetchall()
    best: tuple[int, sqlite3.Row] | None = None
    for cand in candidates:
        if cand["id"] in seen_in_scan:
            continue  # already matched to another host in this same scan
        score = score_candidate(cand, obs, recent_days)
        if best is None or score > best[0]:
            best = (score, cand)

    if best is not None:
        score, cand = best
        if mac is None and score >= IP_ANCHOR_THRESHOLD and cand["current_ip"] == obs.ip:
            return Resolution(cand["id"], False, "ip-anchored", score)
        if mac is not None and score >= MERGE_THRESHOLD:
            return Resolution(cand["id"], False, "heuristic", score)

    return Resolution(-1, True, "created", 0)
