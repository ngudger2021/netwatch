"""Scan job lifecycle: queueing, overlap prevention, cancellation, recovery.

Only one job may be queued or running at a time. Manual requests get HTTP 409
if another job is active; scheduled jobs are simply skipped that cycle. The
runner also takes an exclusive flock so two scheduler processes can never scan
concurrently.
"""
from __future__ import annotations

import fcntl
import json
import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from app.database.connection import transaction, utc_now
from app.scanners.targets import ScanRequest


class ActiveJobError(RuntimeError):
    pass


def active_job(conn: sqlite3.Connection) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT * FROM scan_jobs WHERE status IN ('queued','running') ORDER BY id LIMIT 1").fetchone()


def create_job(conn: sqlite3.Connection, req: ScanRequest, *, trigger: str, requested_by: str = "") -> int:
    with transaction(conn):
        if active_job(conn) is not None:
            raise ActiveJobError("another scan is already queued or running")
        params = {"networks": list(req.networks), "targets": list(req.targets), "ports": req.ports,
                  "concurrency": req.concurrency, "host_timeout": req.host_timeout,
                  "service_detection": req.service_detection}
        cur = conn.execute(
            "INSERT INTO scan_jobs(profile, trigger, requested_by, params, status, progress, created_at) "
            "VALUES (?,?,?,?, 'queued', 'waiting for runner', ?)",
            (req.profile, trigger, requested_by, json.dumps(params), utc_now()))
        return cur.lastrowid


def claim_next(conn: sqlite3.Connection) -> sqlite3.Row | None:
    with transaction(conn):
        row = conn.execute(
            "SELECT * FROM scan_jobs WHERE status = 'queued' ORDER BY id LIMIT 1").fetchone()
        if row is None:
            return None
        conn.execute(
            "UPDATE scan_jobs SET status='running', started_at=?, progress='starting' WHERE id=?",
            (utc_now(), row["id"]))
    return conn.execute("SELECT * FROM scan_jobs WHERE id = ?", (row["id"],)).fetchone()


def request_cancel(conn: sqlite3.Connection, job_id: int) -> str:
    with transaction(conn):
        row = conn.execute("SELECT status FROM scan_jobs WHERE id = ?", (job_id,)).fetchone()
        if row is None:
            raise KeyError(job_id)
        if row["status"] == "queued":
            conn.execute("UPDATE scan_jobs SET status='cancelled', finished_at=?, progress='cancelled before start' "
                         "WHERE id=?", (utc_now(), job_id))
            return "cancelled"
        if row["status"] == "running":
            conn.execute("UPDATE scan_jobs SET cancel_requested=1, progress='cancel requested' WHERE id=?", (job_id,))
            return "cancel-requested"
    return row["status"]


def cancel_requested(conn: sqlite3.Connection, job_id: int) -> bool:
    row = conn.execute("SELECT cancel_requested FROM scan_jobs WHERE id = ?", (job_id,)).fetchone()
    return bool(row and row["cancel_requested"])


def set_progress(conn: sqlite3.Connection, job_id: int, text: str, log_line: str = "") -> None:
    with transaction(conn):
        if log_line:
            conn.execute(
                "UPDATE scan_jobs SET progress=?, log = substr(log || ? || char(10), -20000) WHERE id=?",
                (text, f"[{utc_now()}] {log_line}", job_id))
        else:
            conn.execute("UPDATE scan_jobs SET progress=? WHERE id=?", (text, job_id))


def finish(conn: sqlite3.Connection, job_id: int, status: str, *, error: str = "",
           hosts_up: int = 0, hosts_total: int = 0, nmap_args: str = "") -> None:
    with transaction(conn):
        row = conn.execute("SELECT started_at FROM scan_jobs WHERE id = ?", (job_id,)).fetchone()
        finished = utc_now()
        duration = None
        if row and row["started_at"]:
            from app.database.connection import parse_ts
            duration = (parse_ts(finished) - parse_ts(row["started_at"])).total_seconds()
        conn.execute(
            """UPDATE scan_jobs SET status=?, error=?, finished_at=?, duration_seconds=?,
               hosts_up = hosts_up + ?, hosts_total = hosts_total + ?, nmap_args = CASE WHEN ?='' THEN nmap_args ELSE ? END,
               progress = ? WHERE id=?""",
            (status, error[:2000], finished, duration, hosts_up, hosts_total, nmap_args, nmap_args,
             status, job_id))


def recover_interrupted(conn: sqlite3.Connection) -> int:
    """Mark jobs left 'running' by a crash or power cut as failed."""
    with transaction(conn):
        cur = conn.execute(
            "UPDATE scan_jobs SET status='failed', error='interrupted (service restart or power loss)', "
            "finished_at=?, progress='interrupted' WHERE status='running'", (utc_now(),))
        return cur.rowcount


@contextmanager
def runner_lock(lock_path: str | os.PathLike) -> Iterator[bool]:
    """Non-blocking exclusive lock. Yields False if another runner already holds it."""
    path = Path(lock_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fh = open(path, "a+")
    acquired = False
    try:
        try:
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            acquired = True
        except BlockingIOError:
            acquired = False
        yield acquired
    finally:
        if acquired:
            fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
        fh.close()
