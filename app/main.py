"""FastAPI application factory.

Run (development):   python -m app.cli serve
Run (production):    uvicorn app.main:create_app --factory --host 127.0.0.1 --port 8787
"""
from __future__ import annotations

import logging
import os
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles

from app import __version__
from app.api import auth_routes, pages, routes
from app.api.pages import LoginRequired
from app.config import Settings, load_settings
from app.database import init_database
from app.security.auth import LoginRateLimiter
from app.services.bootstrap import seed_defaults

STATIC_DIR = Path(__file__).resolve().parent / "static"

CSP = (
    "default-src 'self'; "
    "script-src 'self' https://cdn.jsdelivr.net; "
    "style-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; "
    "img-src 'self' data:; font-src 'self' https://cdn.jsdelivr.net; "
    "connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
)


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or load_settings(os.environ.get("NETWATCH_CONFIG"))
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    conn = init_database(settings.db_path)
    seed_defaults(conn, settings)
    conn.close()

    app = FastAPI(
        title="Kali NetWatch API",
        version=__version__,
        description="Network discovery, inventory, change detection and security auditing for Kali on Raspberry Pi. "
                    "Authenticate with the browser login (session cookie). State-changing requests require the "
                    "`X-CSRF-Token` header returned by `/api/v1/auth/login`.",
        docs_url="/api/docs",
        openapi_url="/api/openapi.json",
        redoc_url=None,
    )
    app.state.settings = settings
    app.state.limiter = LoginRateLimiter()

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers.setdefault("Content-Security-Policy", CSP)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "same-origin")
        response.headers.setdefault("Cache-Control", "no-store" if request.url.path.startswith("/api/") else "private")
        return response

    @app.exception_handler(LoginRequired)
    async def _login_redirect(request: Request, exc: LoginRequired):
        return RedirectResponse("/login", status_code=303)

    app.include_router(auth_routes.router)
    app.include_router(routes.router)
    app.include_router(pages.router)
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
    return app

