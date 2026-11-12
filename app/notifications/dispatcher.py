"""Turns persisted events into notifications according to alert_rules.

Processing is cursor-based: every event id above the stored cursor is evaluated
exactly once, whichever process created it. Cooldowns are enforced by looking
at notification_history, so they survive restarts.
"""
from __future__ import annotations

import logging
import sqlite3
from datetime import datetime, timedelta, timezone

from app.config import Settings, telegram_credentials
from app.database.connection import parse_ts, transaction, utc_now
from app.notifications import telegram
from app.security.auth import safe_error_text
from app.services.audit import severity_at_least
from app.services.bootstrap import get_setting, set_setting

log = logging.getLogger("netwatch.dispatch")
CURSOR_KEY = "notify_cursor_event_id"


def _record(conn, event_type: str, dedupe: str, status: str, message: str, error: str = "") -> None:
    with transaction(conn):
        conn.execute(
            "INSERT INTO notification_history(created_at, channel, event_type, dedupe_key, status, message, error) "
            "VALUES (?, 'telegram', ?, ?, ?, ?, ?)",
            (utc_now(), event_type, dedupe, status, message[:1000], error[:300]))


def _recently_sent(conn, dedupe: str, cooldown: int) -> bool:
    if cooldown <= 0:
        return False
    row = conn.execute(
        "SELECT created_at FROM notification_history WHERE dedupe_key = ? AND status IN ('sent','suppressed') "
        "ORDER BY id DESC LIMIT 1", (dedupe,)).fetchone()
    if not row:
        return False
    last = parse_ts(row["created_at"])
    return datetime.now(timezone.utc) - last < timedelta(seconds=cooldown)


def dispatch_pending(conn: sqlite3.Connection, settings: Settings, send=telegram.send) -> int:
    """Evaluate all events newer than the cursor. Returns number of events processed."""
    cursor = int(get_setting(conn, CURSOR_KEY, "0") or 0)
    rows = conn.execute(
        "SELECT * FROM events WHERE id > ? ORDER BY id LIMIT 500", (cursor,)).fetchall()
    if not rows:
        return 0
    rules = {r["event_type"]: r for r in conn.execute("SELECT * FROM alert_rules")}
    enabled = settings.telegram.enabled and telegram_credentials() is not None
    for row in rows:
        rule = rules.get(row["type"])
        if rule is None or not rule["enabled"] or not enabled:
            continue
        if not severity_at_least(row["severity"], rule["min_severity"]):
            continue
        dedupe = f"{row['type']}:{row['device_id']}:{row['title'][:60]}"
        cooldown = rule["cooldown_seconds"] or settings.telegram.cooldown_seconds
        if _recently_sent(conn, dedupe, cooldown):
            _record(conn, row["type"], dedupe, "suppressed", row["title"], "cooldown")
            continue
        event = {"type": row["type"], "severity": row["severity"], "title": row["title"],
                 "created_at": row["created_at"], "details": {}}
        message = telegram.format_event(event)
        try:
            send(message)
            _record(conn, row["type"], dedupe, "sent", row["title"])
        except telegram.TelegramError as exc:
            log.warning("telegram send failed: %s", safe_error_text(exc))
            _record(conn, row["type"], dedupe, "failed", row["title"], str(exc))
    set_setting(conn, CURSOR_KEY, str(rows[-1]["id"]))
    return len(rows)
