"""Idempotent seeding of defaults: networks from config, alert rules, settings."""
from __future__ import annotations

import sqlite3

from app.config import Settings
from app.database.connection import transaction, utc_now

DEFAULT_ALERT_RULES = [
    # event type,           enabled, min severity, cooldown seconds
    ("device_new",          1, "low",    0),
    ("device_offline",      1, "medium", 1800),
    ("device_returned",     0, "info",   900),
    ("port_opened",         1, "medium", 900),
    ("port_closed",         0, "info",   900),
    ("finding_new",         1, "high",   3600),
    ("finding_resolved",    0, "info",   3600),
    ("scan_failed",         1, "high",   1800),
    ("app_error",           1, "high",   1800),
    ("daily_summary",       1, "info",   0),
    ("ip_changed",          0, "info",   900),
    ("hostname_changed",    0, "info",   900),
    ("service_changed",     1, "low",    900),
]


def seed_defaults(conn: sqlite3.Connection, settings: Settings) -> None:
    now = utc_now()
    with transaction(conn):
        for cidr in settings.networks.cidrs:
            conn.execute(
                "INSERT OR IGNORE INTO networks(cidr, name, enabled, is_local, created_at) VALUES (?, '', 1, 0, ?)",
                (cidr, now))
        for event_type, enabled, sev, cooldown in DEFAULT_ALERT_RULES:
            conn.execute(
                "INSERT OR IGNORE INTO alert_rules(event_type, enabled, min_severity, cooldown_seconds) "
                "VALUES (?,?,?,?)", (event_type, enabled, sev, cooldown))
        conn.execute(
            "INSERT OR IGNORE INTO app_settings(key, value, updated_at) VALUES ('setup_complete', '0', ?)", (now,))


def get_setting(conn: sqlite3.Connection, key: str, default: str = "") -> str:
    row = conn.execute("SELECT value FROM app_settings WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else default


def set_setting(conn: sqlite3.Connection, key: str, value: str) -> None:
    with transaction(conn):
        conn.execute(
            "INSERT INTO app_settings(key, value, updated_at) VALUES (?,?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
            (key, value, utc_now()))
