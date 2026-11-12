"""Login / logout endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field

from app.api.deps import audit, client_ip, current_session, get_conn, get_settings
from app.config import Settings
from app.security.auth import (SESSION_COOKIE, authenticate, create_session, csrf_ok,
                               delete_session)

router = APIRouter()


class LoginBody(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


def _same_origin(request: Request) -> bool:
    origin = request.headers.get("origin")
    if not origin:
        return True
    host = request.headers.get("host", "")
    return origin.rstrip("/").endswith("://" + host)


@router.post("/api/v1/auth/login", tags=["auth"])
def login(body: LoginBody, request: Request, response: Response, conn=Depends(get_conn),
          settings: Settings = Depends(get_settings)):
    if not _same_origin(request):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "cross-origin login refused")
    limiter = request.app.state.limiter
    ip = client_ip(request)
    wait = limiter.blocked(ip)
    if wait > 0:
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "too many failed attempts; try again later",
                            headers={"Retry-After": str(int(wait) + 1)})
    user = authenticate(conn, body.username, body.password)
    if user is None:
        limiter.record_failure(ip)
        audit(conn, body.username[:64], "login_failed", ip=ip)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid username or password")
    limiter.record_success(ip)
    raw, csrf = create_session(conn, user["id"], ip, settings.app.session_ttl_hours)
    conn.execute("UPDATE users SET last_login_at = strftime('%Y-%m-%dT%H:%M:%SZ','now') WHERE id = ?", (user["id"],))
    audit(conn, user["username"], "login", ip=ip)
    response.set_cookie(
        SESSION_COOKIE, raw, max_age=settings.app.session_ttl_hours * 3600, httponly=True,
        samesite="strict", secure=settings.app.secure_cookies, path="/")
    return {"ok": True, "username": user["username"], "role": user["role"], "csrf_token": csrf}


@router.post("/api/v1/auth/logout", tags=["auth"])
def logout(request: Request, response: Response, conn=Depends(get_conn), session=Depends(current_session)):
    if session is not None and not csrf_ok(session, request.headers.get("x-csrf-token")):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "missing or invalid CSRF token")
    if session is not None:
        audit(conn, session["username"], "logout", ip=client_ip(request))
    delete_session(conn, request.cookies.get(SESSION_COOKIE))
    response.delete_cookie(SESSION_COOKIE, path="/")
    return {"ok": True}


@router.get("/api/v1/auth/me", tags=["auth"])
def me(session=Depends(current_session)):
    if session is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "authentication required")
    return {"username": session["username"], "role": session["role"], "csrf_token": session["csrf"]}
