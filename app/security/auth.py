"""Password hashing, sessions, CSRF tokens and login rate limiting.

* Passwords: scrypt (stdlib hashlib), per-password random salt, constant-time compare.
* Sessions: random 256-bit token in an HttpOnly/SameSite=Strict cookie; only its
  SHA-256 is stored, so a database copy cannot be replayed as a session.
* CSRF: each session has a token that state-changing requests must echo in the
  X-CSRF-Token header.
* Rate limiting: in-memory per client IP, sliding window with lockout.
"""
from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import sqlite3
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone

from app.database.connection import utc_now

SCRYPT_N, SCRYPT_R, SCRYPT_P = 2**14, 8, 1
MIN_PASSWORD_LENGTH = 12
SESSION_COOKIE = "netwatch_session"
_USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")


class AuthError(ValueError):
    pass


def validate_username(name: str) -> str:
    if not _USERNAME_RE.match(name or ""):
        raise AuthError("username must be 3-32 characters: letters, digits, _ . -")
    return name


def validate_password(password: str) -> str:
    if len(password or "") < MIN_PASSWORD_LENGTH:
        raise AuthError(f"password must be at least {MIN_PASSWORD_LENGTH} characters")
    if password.strip() != password or not password.isprintable():
        raise AuthError("password must not start/end with spaces or contain control characters")
    return password


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P,
                            dklen=32)
    return f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, n, r, p, salt_hex, digest_hex = stored.split("$")
        if scheme != "scrypt":
            return False
        candidate = hashlib.scrypt(password.encode("utf-8"), salt=bytes.fromhex(salt_hex),
                                   n=int(n), r=int(r), p=int(p), dklen=len(digest_hex) // 2)
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(candidate.hex(), digest_hex)


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def create_session(conn: sqlite3.Connection, user_id: int, client_ip: str, ttl_hours: int) -> tuple[str, str]:
    """Create a session. Returns (raw_cookie_token, csrf_token)."""
    raw = secrets.token_urlsafe(32)
    csrf = secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc)
    expires = now + timedelta(hours=ttl_hours)
    conn.execute(
        "INSERT INTO sessions(token_hash, user_id, csrf_token, created_at, expires_at, client_ip) "
        "VALUES (?,?,?,?,?,?)",
        (_sha256(raw), user_id, csrf, now.strftime("%Y-%m-%dT%H:%M:%SZ"),
         expires.strftime("%Y-%m-%dT%H:%M:%SZ"), client_ip))
    return raw, csrf


def load_session(conn: sqlite3.Connection, raw: str | None) -> dict | None:
    if not raw:
        return None
    row = conn.execute(
        """SELECT s.csrf_token, s.expires_at, u.id AS user_id, u.username, u.role, u.disabled, s.token_hash
           FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ?""",
        (_sha256(raw),)).fetchone()
    if row is None:
        return None
    if row["disabled"]:
        return None
    expires = datetime.strptime(row["expires_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    if expires < datetime.now(timezone.utc):
        conn.execute("DELETE FROM sessions WHERE token_hash = ?", (row["token_hash"],))
        return None
    return {"user_id": row["user_id"], "username": row["username"], "role": row["role"],
            "csrf": row["csrf_token"], "token_hash": row["token_hash"]}


def delete_session(conn: sqlite3.Connection, raw: str | None) -> None:
    if raw:
        conn.execute("DELETE FROM sessions WHERE token_hash = ?", (_sha256(raw),))


def purge_expired_sessions(conn: sqlite3.Connection) -> None:
    conn.execute("DELETE FROM sessions WHERE expires_at < ?", (utc_now(),))


def csrf_ok(session: dict | None, header_value: str | None) -> bool:
    if not session or not header_value:
        return False
    return hmac.compare_digest(session["csrf"], header_value)


def safe_error_text(exc: BaseException) -> str:
    """Error text safe for logs and notifications (never includes tokens/URLs)."""
    return type(exc).__name__ + (": " + re.sub(r"https?://\S+", "[url]", str(exc))[:200] if str(exc) else "")


class LoginRateLimiter:
    """Blocks an IP after `max_failures` failed logins within `window` seconds for `lockout` seconds."""

    def __init__(self, max_failures: int = 5, window: float = 900, lockout: float = 900, clock=time.monotonic):
        self.max_failures = max_failures
        self.window = window
        self.lockout = lockout
        self._clock = clock
        self._failures: dict[str, deque] = defaultdict(deque)
        self._locked_until: dict[str, float] = {}
        self._lock = threading.Lock()

    def blocked(self, ip: str) -> float:
        """Seconds remaining in lockout, or 0."""
        with self._lock:
            until = self._locked_until.get(ip, 0)
            remaining = until - self._clock()
            return max(0.0, remaining)

    def record_failure(self, ip: str) -> None:
        with self._lock:
            now = self._clock()
            q = self._failures[ip]
            q.append(now)
            while q and now - q[0] > self.window:
                q.popleft()
            if len(q) >= self.max_failures:
                self._locked_until[ip] = now + self.lockout
                q.clear()

    def record_success(self, ip: str) -> None:
        with self._lock:
            self._failures.pop(ip, None)
            self._locked_until.pop(ip, None)


def authenticate(conn: sqlite3.Connection, username: str, password: str) -> sqlite3.Row | None:
    row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    # Always run one scrypt verification so response time does not reveal valid usernames.
    stored = row["password_hash"] if row else hash_password("not-a-real-password-placeholder")
    ok = verify_password(password, stored)
    if row is None or row["disabled"] or not ok:
        return None
    return row
