import pytest

from app.database.connection import utc_now
from app.notifications import dispatcher, telegram
from app.security.auth import safe_error_text


def _event(conn, type_="device_offline", severity="medium", title="Device offline: printer", device_id=None):
    conn.execute("INSERT INTO events(created_at, type, severity, device_id, title, details) VALUES (?,?,?,?,?,'{}')",
                 (utc_now(), type_, severity, device_id, title))


def test_format_event_escapes_html_and_shows_severity_icon():
    text = telegram.format_event({"type": "port_opened", "severity": "high",
                                  "title": "<script>alert(1)</script> opened", "created_at": "2026-01-01T00:00:00Z",
                                  "details": {"evidence": "a & b"}})
    assert "&lt;script&gt;" in text and "<script>" not in text
    assert "🔴" in text and "a &amp; b" in text


def test_format_summary_contains_counts():
    text = telegram.format_summary({"devices": 27, "online": 20, "offline": 7, "new_24h": 1, "open_ports": 40,
                                    "open_findings": 3, "high_findings": 1, "last_scan": "2026-01-01T00:00:00Z"})
    assert "Devices: 27" in text and "Open findings: 3" in text


def test_disabled_telegram_records_nothing_but_advances_cursor(conn, settings):
    _event(conn)
    sent = []
    n = dispatcher.dispatch_pending(conn, settings, send=lambda t: sent.append(t))
    assert n == 1 and sent == []
    assert conn.execute("SELECT COUNT(*) FROM notification_history").fetchone()[0] == 0
    assert dispatcher.dispatch_pending(conn, settings, send=lambda t: sent.append(t)) == 0  # each event once


def test_enabled_sends_then_cooldown_suppresses(conn, settings, monkeypatch):
    settings.telegram.enabled = True
    monkeypatch.setattr(dispatcher, "telegram_credentials", lambda: ("tok", "chat"))
    sent = []
    _event(conn, title="Device offline: printer")
    dispatcher.dispatch_pending(conn, settings, send=lambda t: sent.append(t))
    _event(conn, title="Device offline: printer")   # identical, inside cooldown
    dispatcher.dispatch_pending(conn, settings, send=lambda t: sent.append(t))
    statuses = [r[0] for r in conn.execute("SELECT status FROM notification_history ORDER BY id")]
    assert statuses == ["sent", "suppressed"]
    assert len(sent) == 1


def test_below_rule_severity_is_not_sent(conn, settings, monkeypatch):
    settings.telegram.enabled = True
    monkeypatch.setattr(dispatcher, "telegram_credentials", lambda: ("tok", "chat"))
    _event(conn, type_="port_opened", severity="info", title="Port 80 opened")   # rule min is medium
    sent = []
    dispatcher.dispatch_pending(conn, settings, send=lambda t: sent.append(t))
    assert sent == []


def test_disabled_rule_is_not_sent(conn, settings, monkeypatch):
    settings.telegram.enabled = True
    monkeypatch.setattr(dispatcher, "telegram_credentials", lambda: ("tok", "chat"))
    conn.execute("UPDATE alert_rules SET enabled=0 WHERE event_type='device_offline'")
    _event(conn)
    sent = []
    dispatcher.dispatch_pending(conn, settings, send=lambda t: sent.append(t))
    assert sent == []


def test_send_failure_is_recorded_without_token(conn, settings, monkeypatch):
    settings.telegram.enabled = True
    monkeypatch.setattr(dispatcher, "telegram_credentials", lambda: ("123:SECRET", "chat"))

    def boom(_text):
        raise telegram.TelegramError("Telegram API returned HTTP 401")

    _event(conn, title="Device offline: tv")
    dispatcher.dispatch_pending(conn, settings, send=boom)
    row = conn.execute("SELECT status, error FROM notification_history").fetchone()
    assert row["status"] == "failed" and "401" in row["error"]
    assert "SECRET" not in row["error"]


def test_send_without_credentials_raises_clear_error(monkeypatch):
    monkeypatch.delenv("NETWATCH_TELEGRAM_BOT_TOKEN", raising=False)
    monkeypatch.delenv("NETWATCH_TELEGRAM_CHAT_ID", raising=False)
    with pytest.raises(telegram.TelegramError, match="not configured"):
        telegram.send("hello")


def test_network_error_message_hides_url(monkeypatch):
    import httpx
    monkeypatch.setenv("NETWATCH_TELEGRAM_BOT_TOKEN", "999:TOPSECRET")
    monkeypatch.setenv("NETWATCH_TELEGRAM_CHAT_ID", "42")

    def fail(*a, **k):
        raise httpx.ConnectError("failed for https://api.telegram.org/bot999:TOPSECRET/sendMessage")

    monkeypatch.setattr(telegram.httpx, "post", fail)
    with pytest.raises(telegram.TelegramError) as exc:
        telegram.send("hi")
    assert "TOPSECRET" not in str(exc.value)


def test_safe_error_text_strips_urls():
    assert "TOKEN" not in safe_error_text(RuntimeError("see https://x.example/bot1:TOKEN/send"))
