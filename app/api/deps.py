"""FastAPI dependencies: settings, per-request DB connection, session, roles, CSRF."""
from __future__ import annotations

from typing import Iterator

from fastapi import Depends, HTTPException, Request, status

from app.config import Settings
from app.database import connect
from app.database.connection import utc_now
from app.security.auth import SESSION_COOKIE, csrf_ok, load_session


def get_settings(request: Request) -> Settings:
    return request.app.state.settings


def get_conn(request: Request) -> Iterator:
    conn = connect(request.app.state.settings.db_path)
    try:
        yield conn
    finally:
        conn.close()


def current_session(request: Request, conn=Depends(get_conn)) -> dict | None:
    raw = request.cookies.get(SESSION_COOKIE)
    session = load_session(conn, raw)
    if session is not None:
        session["client_ip"] = client_ip(request)
    return session


def require_viewer(session: dict | None = Depends(current_session)) -> dict:
    if session is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "authentication required")
    return session


def require_admin(session: dict = Depends(require_viewer)) -> dict:
    if session["role"] != "admin":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "administrator role required")
    return session


def require_admin_csrf(request: Request, session: dict = Depends(require_admin)) -> dict:
    if not csrf_ok(session, request.headers.get("x-csrf-token")):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "missing or invalid CSRF token")
    return session


def client_ip(request: Request) -> str:
    # The app binds to localhost or the LAN and does not trust X-Forwarded-For; the reverse
    # proxy (if any) is expected to be on the same host and the address is taken from the socket.
    return request.client.host if request.client else ""


def audit(conn, user: str, action: str, target: str = "", detail: str = "", ip: str = "") -> None:
    conn.execute(
        "INSERT INTO audit_log(created_at, username, action, target, detail, client_ip) VALUES (?,?,?,?,?,?)",
        (utc_now(), user, action, target, detail[:500], ip))
