"""Telegram Bot API client and message formatting.

Only the bot token and chat id come from the environment. Error messages are
reduced to the exception class name because httpx errors can embed the request
URL, which contains the token.
"""
from __future__ import annotations

import html
import logging

import httpx

from app.config import telegram_credentials

log = logging.getLogger("netwatch.telegram")
API = "https://api.telegram.org/bot{token}/sendMessage"
SEVERITY_ICON = {"critical": "🛑", "high": "🔴", "medium": "🟠", "low": "🟡", "info": "🔵"}


class TelegramError(RuntimeError):
    pass


def format_event(event: dict) -> str:
    icon = SEVERITY_ICON.get(event.get("severity", "info"), "🔵")
    title = html.escape(event.get("title", "Network event"))
    kind = html.escape(event.get("type", "event").replace("_", " ").title())
    lines = [f"{icon} <b>{kind}</b>", title]
    details = event.get("details") or {}
    if isinstance(details, dict):
        for key in ("evidence", "reason", "last_seen", "status"):
            if details.get(key):
                lines.append(f"{html.escape(key)}: {html.escape(str(details[key]))[:300]}")
    when = event.get("created_at", "")
    if when:
        lines.append(f"<i>{html.escape(when)}</i>")
    return "\n".join(lines)


def format_summary(stats: dict) -> str:
    return "\n".join([
        "📊 <b>Kali NetWatch daily summary</b>",
        f"Devices: {stats.get('devices', 0)} (online {stats.get('online', 0)}, offline {stats.get('offline', 0)})",
        f"New devices (24h): {stats.get('new_24h', 0)}",
        f"Open ports: {stats.get('open_ports', 0)}",
        f"Open findings: {stats.get('open_findings', 0)} (high or critical: {stats.get('high_findings', 0)})",
        f"Last successful scan: {stats.get('last_scan', 'never')}",
    ])


def format_test() -> str:
    return "✅ <b>Kali NetWatch</b> test message: Telegram notifications are working."


def send(text: str, *, timeout: float = 10.0) -> None:
    creds = telegram_credentials()
    if creds is None:
        raise TelegramError("Telegram is not configured (NETWATCH_TELEGRAM_BOT_TOKEN / _CHAT_ID)")
    token, chat_id = creds
    try:
        resp = httpx.post(
            API.format(token=token),
            data={"chat_id": chat_id, "text": text[:4000], "parse_mode": "HTML",
                  "disable_web_page_preview": "true"},
            timeout=timeout,
        )
    except httpx.HTTPError as exc:
        raise TelegramError(f"network error ({type(exc).__name__})") from None
    if resp.status_code != 200:
        raise TelegramError(f"Telegram API returned HTTP {resp.status_code}")
