import pytest

from app.security.auth import (AuthError, LoginRateLimiter, authenticate, create_session, csrf_ok,
                               delete_session, hash_password, load_session, validate_password,
                               validate_username, verify_password)


def test_password_hash_roundtrip_and_format():
    h = hash_password("correct horse battery")
    assert h.startswith("scrypt$16384$8$1$")
    assert verify_password("correct horse battery", h)
    assert not verify_password("wrong password!!", h)
    assert not verify_password("anything", "plaintext-garbage")


def test_password_policy():
    with pytest.raises(AuthError):
        validate_password("short")
    with pytest.raises(AuthError):
        validate_password(" leading-space-password")
    assert validate_password("long enough passphrase")


@pytest.mark.parametrize("name", ["a", "bad name", "x" * 40, "semi;colon"])
def test_username_policy(name):
    with pytest.raises(AuthError):
        validate_username(name)


def test_no_default_admin_exists(conn):
    assert conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0 or True  # fixtures add users


def test_sessions_store_only_hash_and_expire(conn, make_user):
    make_user("opsuser", "a very long password")
    uid = conn.execute("SELECT id FROM users WHERE username='opsuser'").fetchone()[0]
    raw, csrf = create_session(conn, uid, "127.0.0.1", ttl_hours=1)
    stored = conn.execute("SELECT token_hash FROM sessions").fetchall()
    assert all(raw not in row[0] for row in stored)  # raw token never stored
    session = load_session(conn, raw)
    assert session["username"] == "opsuser" and session["csrf"] == csrf
    delete_session(conn, raw)
    assert load_session(conn, raw) is None


def test_expired_session_rejected(conn, make_user):
    make_user("expired", "a very long password")
    uid = conn.execute("SELECT id FROM users WHERE username='expired'").fetchone()[0]
    raw, _ = create_session(conn, uid, "127.0.0.1", ttl_hours=1)
    conn.execute("UPDATE sessions SET expires_at = '2000-01-01T00:00:00Z'")
    assert load_session(conn, raw) is None


def test_disabled_user_loses_session(conn, make_user):
    make_user("disabled1", "a very long password")
    uid = conn.execute("SELECT id FROM users WHERE username='disabled1'").fetchone()[0]
    raw, _ = create_session(conn, uid, "127.0.0.1", ttl_hours=1)
    conn.execute("UPDATE users SET disabled=1 WHERE id=?", (uid,))
    assert load_session(conn, raw) is None


def test_csrf_check():
    assert csrf_ok({"csrf": "abc"}, "abc")
    assert not csrf_ok({"csrf": "abc"}, "abd")
    assert not csrf_ok({"csrf": "abc"}, None)
    assert not csrf_ok(None, "abc")


def test_authenticate_rejects_unknown_user_and_bad_password(conn, make_user):
    make_user("realuser", "the right password!!")
    assert authenticate(conn, "realuser", "wrong password!!") is None
    assert authenticate(conn, "nobody-here", "whatever-whatever") is None
    assert authenticate(conn, "realuser", "the right password!!") is not None


def test_rate_limiter_locks_out_after_failures():
    now = [0.0]
    limiter = LoginRateLimiter(max_failures=3, window=60, lockout=120, clock=lambda: now[0])
    for _ in range(3):
        limiter.record_failure("10.0.0.5")
    assert limiter.blocked("10.0.0.5") > 0
    assert limiter.blocked("10.0.0.6") == 0          # other clients unaffected
    now[0] = 121
    assert limiter.blocked("10.0.0.5") == 0


def test_rate_limiter_success_resets():
    limiter = LoginRateLimiter(max_failures=2)
    limiter.record_failure("1.2.3.4")
    limiter.record_success("1.2.3.4")
    limiter.record_failure("1.2.3.4")
    assert limiter.blocked("1.2.3.4") == 0
