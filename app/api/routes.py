"""JSON API under /api/v1. Interactive OpenAPI docs are served at /api/docs."""
from __future__ import annotations

import json
import sqlite3
from typing import Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import Response as RawResponse
from pydantic import BaseModel, Field, field_validator

from app.api.deps import audit, client_ip, get_conn, get_settings, require_admin, require_admin_csrf, require_viewer
from app.config import Settings, validate_cidr
from app.database.connection import transaction, utc_now
from app.notifications import dispatcher, telegram
from app.scanners.targets import ScanRequest, ValidationError, validate_request
from app.services import jobs, queries, reports
from app.services.health import system_snapshot
from app.config import telegram_credentials

router = APIRouter(prefix="/api/v1")
DEVICE_TYPES = ("unknown", "router", "server", "workstation", "media", "camera", "printer",
                "smart-home", "server-mgmt", "single-board")
SEVERITIES = Literal["info", "low", "medium", "high", "critical"]


# ---------- request models ------------------------------------------------
class DeviceUpdate(BaseModel):
    custom_name: Optional[str] = Field(None, max_length=64)
    description: Optional[str] = Field(None, max_length=200)
    notes: Optional[str] = Field(None, max_length=4000)
    trusted: Optional[bool] = None
    device_type: Optional[Literal["unknown", "router", "server", "workstation", "media", "camera", "printer",
                                  "smart-home", "server-mgmt", "single-board"]] = None


class NetworkCreate(BaseModel):
    cidr: str = Field(max_length=32)
    name: str = Field("", max_length=64)

    @field_validator("cidr")
    @classmethod
    def _cidr(cls, v: str) -> str:
        return validate_cidr(v)


class NetworkUpdate(BaseModel):
    name: Optional[str] = Field(None, max_length=64)
    enabled: Optional[bool] = None


class ScanCreate(BaseModel):
    profile: Literal["quick", "standard", "detailed", "custom"]
    networks: list[str] = Field(default_factory=list, max_length=8)
    targets: list[str] = Field(default_factory=list, max_length=32)
    ports: str = Field("", max_length=400)
    concurrency: Optional[int] = Field(None, ge=1, le=64)
    host_timeout: Optional[int] = Field(None, ge=30, le=3600)
    service_detection: bool = True


class AlertRuleItem(BaseModel):
    event_type: str = Field(max_length=40)
    enabled: bool
    min_severity: SEVERITIES
    cooldown_seconds: int = Field(ge=0, le=86400)


class AlertRulesUpdate(BaseModel):
    rules: list[AlertRuleItem] = Field(max_length=50)


# ---------- health & system ----------------------------------------------
@router.get("/health", tags=["health"], summary="Public liveness check (no details)")
def health(conn=Depends(get_conn)):
    return {"status": "ok", "time": utc_now()}


@router.get("/system", tags=["health"], summary="Raspberry Pi and service health")
def system(conn=Depends(get_conn), settings: Settings = Depends(get_settings), _=Depends(require_viewer)):
    return system_snapshot(conn, settings.app.data_dir)


# ---------- dashboard ------------------------------------------------------
@router.get("/dashboard", tags=["dashboard"])
def dashboard(conn=Depends(get_conn), settings: Settings = Depends(get_settings), _=Depends(require_viewer)):
    return queries.dashboard(conn, settings)


# ---------- devices --------------------------------------------------------
@router.get("/devices", tags=["devices"], summary="Searchable, filterable device inventory")
def list_devices(
    q: str = Query("", max_length=100),
    network: str = Query("", max_length=32),
    vendor: str = Query("", max_length=100),
    device_type: str = Query("", max_length=32),
    status_: str = Query("", alias="status", pattern="^(|online|offline|unknown)$"),
    risk: str = Query("", pattern="^(|low|medium|high)$"),
    trusted: str = Query("", pattern="^(|0|1)$"),
    sort: str = Query("ip", max_length=20),
    order: str = Query("asc", pattern="^(asc|desc)$"),
    page: int = Query(1, ge=1, le=100000),
    size: int = Query(50, ge=1, le=200),
    conn=Depends(get_conn), _=Depends(require_viewer),
):
    return queries.list_devices(conn, q=q, network=network, vendor=vendor, device_type=device_type,
                                status=status_, risk=risk, trusted=trusted, sort=sort, order=order,
                                page=page, size=size)


@router.get("/devices/{device_id}", tags=["devices"])
def get_device(device_id: int, conn=Depends(get_conn), _=Depends(require_viewer)):
    detail = queries.device_detail(conn, device_id)
    if detail is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "device not found")
    return detail


@router.get("/devices/{device_id}/history", tags=["devices"], summary="Availability and change history")
def device_history(device_id: int, limit: int = Query(200, ge=1, le=1000),
                   conn=Depends(get_conn), _=Depends(require_viewer)):
    if conn.execute("SELECT 1 FROM devices WHERE id = ?", (device_id,)).fetchone() is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "device not found")
    obs = [dict(r) for r in conn.execute(
        "SELECT ip, status, observed_at, job_id FROM device_observations WHERE device_id = ? "
        "ORDER BY id DESC LIMIT ?", (device_id, limit))]
    events = [dict(r) for r in conn.execute(
        "SELECT id, created_at, type, severity, title FROM events WHERE device_id = ? ORDER BY id DESC LIMIT ?",
        (device_id, limit))]
    return {"availability": queries.availability(conn, device_id, 7), "observations": obs, "events": events}


@router.patch("/devices/{device_id}", tags=["devices"], dependencies=[Depends(require_admin_csrf)])
def update_device(device_id: int, body: DeviceUpdate, request: Request, conn=Depends(get_conn),
                  session=Depends(require_admin)):
    if conn.execute("SELECT 1 FROM devices WHERE id = ?", (device_id,)).fetchone() is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "device not found")
    changes = body.model_dump(exclude_unset=True)
    if not changes:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "no fields to update")
    sets, args = [], []
    for key, value in changes.items():
        if key == "trusted":
            value = int(bool(value))
        sets.append(f"{key} = ?")
        args.append(value)
    if "device_type" in changes:
        sets.append("device_type_source = 'user'")
    with transaction(conn):
        conn.execute(f"UPDATE devices SET {', '.join(sets)}, updated_at = ? WHERE id = ?",
                     (*args, utc_now(), device_id))
    audit(conn, session["username"], "device_update", f"device:{device_id}", json.dumps(
        {k: (v if k != "notes" else "[redacted-length=%d]" % len(v or "")) for k, v in changes.items()}),
        client_ip(request))
    return queries.device_detail(conn, device_id)


# ---------- networks -------------------------------------------------------
@router.get("/networks", tags=["networks"])
def list_networks(conn=Depends(get_conn), _=Depends(require_viewer)):
    return queries.list_networks(conn)


@router.post("/networks", tags=["networks"], status_code=201, dependencies=[Depends(require_admin_csrf)])
def create_network(body: NetworkCreate, request: Request, conn=Depends(get_conn), session=Depends(require_admin)):
    try:
        with transaction(conn):
            conn.execute("INSERT INTO networks(cidr, name, enabled, is_local, created_at) VALUES (?,?,1,0,?)",
                         (body.cidr, body.name, utc_now()))
    except sqlite3.IntegrityError:
        raise HTTPException(status.HTTP_409_CONFLICT, "network already configured")
    audit(conn, session["username"], "network_add", body.cidr, body.name, client_ip(request))
    return {"cidr": body.cidr, "name": body.name}


@router.patch("/networks/{network_id}", tags=["networks"], dependencies=[Depends(require_admin_csrf)])
def update_network(network_id: int, body: NetworkUpdate, request: Request, conn=Depends(get_conn),
                   session=Depends(require_admin)):
    row = conn.execute("SELECT * FROM networks WHERE id = ?", (network_id,)).fetchone()
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "network not found")
    changes = body.model_dump(exclude_unset=True)
    with transaction(conn):
        if "name" in changes and changes["name"] is not None:
            conn.execute("UPDATE networks SET name = ? WHERE id = ?", (changes["name"], network_id))
        if "enabled" in changes and changes["enabled"] is not None:
            conn.execute("UPDATE networks SET enabled = ? WHERE id = ?", (int(changes["enabled"]), network_id))
    audit(conn, session["username"], "network_update", row["cidr"], json.dumps(changes), client_ip(request))
    return dict(conn.execute("SELECT * FROM networks WHERE id = ?", (network_id,)).fetchone())


# ---------- scans ----------------------------------------------------------
@router.get("/scans", tags=["scans"])
def list_scans(page: int = Query(1, ge=1, le=100000), size: int = Query(25, ge=1, le=100),
               conn=Depends(get_conn), _=Depends(require_viewer)):
    return queries.list_scans(conn, page, size)


@router.get("/scans/{job_id}", tags=["scans"], summary="Scan detail, progress and log")
def get_scan(job_id: int, conn=Depends(get_conn), _=Depends(require_viewer)):
    detail = queries.scan_detail(conn, job_id)
    if detail is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "scan not found")
    return detail


@router.post("/scans", tags=["scans"], status_code=202, dependencies=[Depends(require_admin_csrf)])
def start_scan(body: ScanCreate, request: Request, conn=Depends(get_conn), settings: Settings = Depends(get_settings),
               session=Depends(require_admin)):
    configured = [r["cidr"] for r in conn.execute("SELECT cidr FROM networks WHERE enabled = 1")]
    if not configured:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "no enabled networks configured")
    if body.profile == "detailed" and not body.networks and not body.targets:
        body.networks = configured
    try:
        req = validate_request(ScanRequest(
            profile=body.profile, networks=tuple(body.networks), targets=tuple(body.targets),
            ports=body.ports, concurrency=body.concurrency, host_timeout=body.host_timeout,
            service_detection=body.service_detection),
            configured, settings.scanning.max_hosts_per_target)
    except ValidationError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc))
    if body.profile in ("quick", "standard", "detailed") and body.ports and body.profile != "detailed":
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "ports apply to detailed and custom scans only")
    try:
        job_id = jobs.create_job(conn, req, trigger="manual", requested_by=session["username"])
    except jobs.ActiveJobError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc))
    audit(conn, session["username"], "scan_start", f"job:{job_id}", body.profile, client_ip(request))
    return {"job_id": job_id, "status": "queued"}


@router.post("/scans/{job_id}/cancel", tags=["scans"], dependencies=[Depends(require_admin_csrf)])
def cancel_scan(job_id: int, request: Request, conn=Depends(get_conn), session=Depends(require_admin)):
    try:
        result = jobs.request_cancel(conn, job_id)
    except KeyError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "scan not found")
    audit(conn, session["username"], "scan_cancel", f"job:{job_id}", result, client_ip(request))
    return {"job_id": job_id, "result": result}


# ---------- findings & events ---------------------------------------------
@router.get("/findings", tags=["security"])
def list_findings(status_: str = Query("open", alias="status", pattern="^(open|resolved|acknowledged|all)$"),
                  severity: str = Query("", pattern="^(|info|low|medium|high|critical)$"),
                  page: int = Query(1, ge=1, le=100000), size: int = Query(50, ge=1, le=200),
                  conn=Depends(get_conn), _=Depends(require_viewer)):
    return queries.list_findings(conn, status="" if status_ == "all" else status_, severity=severity,
                                 page=page, size=size)


@router.post("/findings/{finding_id}/acknowledge", tags=["security"],
             dependencies=[Depends(require_admin_csrf)],
             summary="Acknowledge a finding (it stays visible and keeps scoring)")
def acknowledge(finding_id: int, request: Request, conn=Depends(get_conn), session=Depends(require_admin)):
    row = conn.execute("SELECT id FROM security_findings WHERE id = ?", (finding_id,)).fetchone()
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "finding not found")
    with transaction(conn):
        conn.execute("UPDATE security_findings SET status='acknowledged' WHERE id = ? AND status='open'",
                     (finding_id,))
    audit(conn, session["username"], "finding_acknowledge", f"finding:{finding_id}", "", client_ip(request))
    return {"id": finding_id, "status": "acknowledged"}


@router.get("/events", tags=["events"])
def list_events(type_: str = Query("", alias="type", max_length=40),
                severity: str = Query("", pattern="^(|info|low|medium|high|critical)$"),
                page: int = Query(1, ge=1, le=100000), size: int = Query(50, ge=1, le=200),
                conn=Depends(get_conn), _=Depends(require_viewer)):
    return queries.list_events(conn, type_=type_, severity=severity, page=page, size=size)


# ---------- notifications & settings --------------------------------------
@router.get("/notifications", tags=["notifications"])
def notifications(page: int = Query(1, ge=1, le=100000), size: int = Query(50, ge=1, le=200),
                  conn=Depends(get_conn), _=Depends(require_viewer)):
    return queries.list_notifications(conn, page, size)


@router.post("/notifications/test", tags=["notifications"], dependencies=[Depends(require_admin_csrf)])
def test_notification(request: Request, conn=Depends(get_conn), session=Depends(require_admin),
                      settings: Settings = Depends(get_settings)):
    if telegram_credentials() is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            "Telegram credentials are not set in the environment file")
    try:
        telegram.send(telegram.format_test())
    except telegram.TelegramError as exc:
        dispatcher._record(conn, "test", "test", "failed", "test message", str(exc))
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, str(exc))
    dispatcher._record(conn, "test", "test", "sent", "test message")
    audit(conn, session["username"], "telegram_test", "", "", client_ip(request))
    return {"ok": True}


@router.get("/settings", tags=["settings"])
def get_settings_view(conn=Depends(get_conn), settings: Settings = Depends(get_settings), _=Depends(require_viewer)):
    return {
        "networks": queries.list_networks(conn),
        "scanning": {"privileged": settings.scanning.privileged, "top_ports": settings.scanning.top_ports,
                     "max_parallelism": settings.scanning.max_parallelism,
                     "job_timeout_seconds": settings.scanning.job_timeout_seconds,
                     "host_timeout_seconds": settings.scanning.host_timeout_seconds},
        "schedule": {"enabled": settings.schedule.enabled, "discovery_minutes": settings.schedule.discovery_minutes,
                     "standard_hours": settings.schedule.standard_hours,
                     "summary_hours": settings.schedule.summary_hours},
        "change": {"offline_threshold": settings.change.offline_threshold, "recent_days": settings.change.recent_days},
        "retention_days": settings.app.history_retention_days,
        "telegram": {"enabled": settings.telegram.enabled, "credentials_present": telegram_credentials() is not None,
                     "cooldown_seconds": settings.telegram.cooldown_seconds,
                     "daily_summary": settings.telegram.daily_summary},
        "alert_rules": [dict(r) for r in conn.execute("SELECT * FROM alert_rules ORDER BY event_type")],
    }


@router.put("/settings/alert-rules", tags=["settings"], dependencies=[Depends(require_admin_csrf)])
def update_alert_rules(body: AlertRulesUpdate, request: Request, conn=Depends(get_conn),
                       session=Depends(require_admin)):
    known = {r["event_type"] for r in conn.execute("SELECT event_type FROM alert_rules")}
    unknown = [r.event_type for r in body.rules if r.event_type not in known]
    if unknown:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, f"unknown event types: {unknown}")
    with transaction(conn):
        for r in body.rules:
            conn.execute("UPDATE alert_rules SET enabled=?, min_severity=?, cooldown_seconds=? WHERE event_type=?",
                         (int(r.enabled), r.min_severity, r.cooldown_seconds, r.event_type))
    audit(conn, session["username"], "alert_rules_update", "", str(len(body.rules)), client_ip(request))
    return {"ok": True, "updated": len(body.rules)}


# ---------- reports & audit ------------------------------------------------
@router.get("/reports/{dataset}/{fmt}", tags=["reports"], summary="Download a report (csv, json or html)")
def download_report(dataset: str, fmt: str, conn=Depends(get_conn), _=Depends(require_viewer)):
    if dataset not in reports.DATASETS or fmt not in reports.FORMATS:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "unknown report")
    rows = reports.dataset(conn, dataset)
    body, media, filename = reports.render(dataset, fmt, rows, title=f"Kali NetWatch — {dataset}")
    return RawResponse(content=body, media_type=media,
                       headers={"Content-Disposition": f'attachment; filename="{filename}"'})


@router.get("/audit", tags=["security"], summary="Audit log (administrators)")
def audit_log(page: int = Query(1, ge=1, le=100000), size: int = Query(50, ge=1, le=200),
              conn=Depends(get_conn), _=Depends(require_admin)):
    total = conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
    rows = conn.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT ? OFFSET ?",
                        (size, (page - 1) * size)).fetchall()
    return {"items": [dict(r) for r in rows], "total": total, "page": page, "size": size}
