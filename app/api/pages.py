"""Server-rendered dashboard pages. Data is loaded by JavaScript from /api/v1."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from pathlib import Path

from app.api.deps import current_session

TEMPLATES = Jinja2Templates(directory=str(Path(__file__).resolve().parent.parent / "templates"))
router = APIRouter(include_in_schema=False)


class LoginRequired(Exception):
    pass


def _page(request: Request, template: str, session: dict | None, page_id: str, **ctx) -> HTMLResponse:
    if session is None:
        raise LoginRequired()
    return TEMPLATES.TemplateResponse(request, template, {
        "page_id": page_id, "user": session, "csrf": session["csrf"], **ctx})


@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request, session=Depends(current_session)):
    if session is not None:
        return RedirectResponse("/", status_code=303)
    return TEMPLATES.TemplateResponse(request, "login.html", {"page_id": "login", "user": None, "csrf": ""})


@router.get("/", response_class=HTMLResponse)
def dashboard(request: Request, session=Depends(current_session)):
    return _page(request, "dashboard.html", session, "dashboard")


@router.get("/devices", response_class=HTMLResponse)
def devices(request: Request, session=Depends(current_session)):
    return _page(request, "devices.html", session, "devices")


@router.get("/devices/{device_id}", response_class=HTMLResponse)
def device_detail(device_id: int, request: Request, session=Depends(current_session)):
    return _page(request, "device_detail.html", session, "device", device_id=device_id)


@router.get("/scans", response_class=HTMLResponse)
def scans(request: Request, session=Depends(current_session)):
    return _page(request, "scans.html", session, "scans")


@router.get("/findings", response_class=HTMLResponse)
def findings(request: Request, session=Depends(current_session)):
    return _page(request, "findings.html", session, "findings")


@router.get("/events", response_class=HTMLResponse)
def events(request: Request, session=Depends(current_session)):
    return _page(request, "events.html", session, "events")


@router.get("/reports", response_class=HTMLResponse)
def reports(request: Request, session=Depends(current_session)):
    return _page(request, "reports.html", session, "reports")


@router.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request, session=Depends(current_session)):
    return _page(request, "settings.html", session, "settings")


@router.get("/system", response_class=HTMLResponse)
def system_page(request: Request, session=Depends(current_session)):
    return _page(request, "system.html", session, "system")
