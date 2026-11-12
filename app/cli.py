"""Operator command line.

  python -m app.cli doctor                      check config, nmap, database, tools
  python -m app.cli init-db                     create/upgrade the database
  python -m app.cli create-user NAME --role admin [--password-stdin]
  python -m app.cli reset-password NAME [--password-stdin]
  python -m app.cli scheduler                   run the scheduler/runner (systemd unit)
  python -m app.cli scan --profile quick        queue a scan on the enabled networks and run it now
  python -m app.cli prune                       apply history retention now
  python -m app.cli serve                       development server on the configured bind address
  python -m app.cli backup-db DEST              consistent online copy of the database (sqlite backup API)
  python -m app.cli restore-db SRC              verify (integrity_check) and restore a database copy
"""
from __future__ import annotations

import argparse
import getpass
import logging
import shutil
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

from app.config import load_settings
from app.database import init_database
from app.security.auth import AuthError, hash_password, validate_password, validate_username
from app.services.bootstrap import seed_defaults


def _password(args) -> str:
    if args.password_stdin:
        pw = sys.stdin.readline().rstrip("\n")
    else:
        pw = getpass.getpass("Password (min 12 characters): ")
        if pw != getpass.getpass("Repeat password: "):
            raise SystemExit("passwords do not match")
    return validate_password(pw)


def cmd_doctor(settings, args) -> int:
    problems = 0

    def check(label: str, ok: bool, detail: str = "") -> None:
        nonlocal problems
        problems += 0 if ok else 1
        print(f"[{'ok' if ok else 'FAIL'}] {label}{(' — ' + detail) if detail else ''}")

    check("config loaded", True, str(settings.app.data_dir))
    nmap = shutil.which("nmap") or settings.scanning.nmap_path
    check("nmap available", bool(shutil.which("nmap")) or __import__("os").path.isfile(nmap), nmap)
    check("ip command", shutil.which("ip") is not None)
    check("OUI database", __import__("os").path.isfile(settings.scanning.oui_file), settings.scanning.oui_file)
    try:
        conn = init_database(settings.db_path)
        seed_defaults(conn, settings)
        mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
        check("database writable (WAL)", mode.lower() == "wal", f"{settings.db_path} mode={mode}")
        users = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        check("administrator account exists", users > 0, f"{users} user(s)")
    except (sqlite3.Error, OSError) as exc:
        check("database", False, str(exc))
    from app.config import telegram_credentials
    print(f"[info] telegram: {'enabled' if settings.telegram.enabled else 'disabled'}, "
          f"credentials {'present' if telegram_credentials() else 'absent'}")
    return 0 if problems == 0 else 1


def cmd_create_user(settings, args) -> int:
    try:
        username = validate_username(args.name)
        password = _password(args)
    except AuthError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    conn = init_database(settings.db_path)
    try:
        with conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                "INSERT INTO users(username, password_hash, role, created_at) VALUES (?,?,?,strftime('%Y-%m-%dT%H:%M:%SZ','now'))",
                (username, hash_password(password), args.role))
            conn.execute("COMMIT")
    except sqlite3.IntegrityError:
        print("error: user already exists (use reset-password)", file=sys.stderr)
        return 1
    print(f"created {args.role} '{username}'")
    return 0


def cmd_reset_password(settings, args) -> int:
    try:
        password = _password(args)
    except AuthError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    conn = init_database(settings.db_path)
    conn.execute("BEGIN IMMEDIATE")
    cur = conn.execute("UPDATE users SET password_hash = ? WHERE username = ?", (hash_password(password), args.name))
    conn.execute("DELETE FROM sessions WHERE user_id IN (SELECT id FROM users WHERE username = ?)", (args.name,))
    conn.execute("COMMIT")
    if cur.rowcount == 0:
        print("error: no such user", file=sys.stderr)
        return 1
    print("password updated; existing sessions revoked")
    return 0


def cmd_scan(settings, args) -> int:
    from app.scanners.targets import ScanRequest, ValidationError, validate_request
    from app.services import jobs
    from app.services.scan_executor import execute_job
    conn = init_database(settings.db_path)
    seed_defaults(conn, settings)
    networks = [r["cidr"] for r in conn.execute("SELECT cidr FROM networks WHERE enabled = 1")]
    try:
        req = validate_request(ScanRequest(profile=args.profile, networks=tuple(networks)),
                               networks, settings.scanning.max_hosts_per_target)
        job_id = jobs.create_job(conn, req, trigger="manual", requested_by="cli")
    except (ValidationError, jobs.ActiveJobError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    with jobs.runner_lock(settings.scan_lock_path) as acquired:
        if not acquired:
            print("another runner holds the scan lock; job queued", file=sys.stderr)
            return 0
        job = jobs.claim_next(conn)
        status = execute_job(conn, settings, job)
    print(f"job {job_id}: {status}")
    return 0 if status == "completed" else 1


def cmd_prune(settings, args) -> int:
    from app.services.scheduler import Scheduler
    sched = Scheduler(settings)
    print(sched.prune_history())
    return 0


def cmd_scheduler(settings, args) -> int:
    from app.services.scheduler import Scheduler
    Scheduler(settings).run_forever()
    return 0


def cmd_serve(settings, args) -> int:
    import uvicorn
    uvicorn.run("app.main:create_app", factory=True, host=settings.app.bind_host,
                port=settings.app.bind_port, proxy_headers=False, server_header=False)
    return 0


def cmd_init_db(settings, args) -> int:
    conn = init_database(settings.db_path)
    seed_defaults(conn, settings)
    print(f"database ready at {settings.db_path}")
    return 0


def cmd_backup_db(settings, args) -> int:
    dest = Path(args.dest)
    if dest.exists():
        print(f"error: {dest} already exists", file=sys.stderr)
        return 1
    dest.parent.mkdir(parents=True, exist_ok=True)
    src = sqlite3.connect(str(settings.db_path))
    out = sqlite3.connect(str(dest))
    try:
        src.backup(out)
        check = out.execute("PRAGMA integrity_check").fetchone()[0]
    finally:
        out.close()
        src.close()
    if check != "ok":
        dest.unlink(missing_ok=True)
        print(f"error: backup failed integrity check: {check}", file=sys.stderr)
        return 1
    dest.chmod(0o600)
    print(f"database backed up to {dest}")
    return 0


def cmd_restore_db(settings, args) -> int:
    src = Path(args.src)
    if not src.is_file():
        print(f"error: {src} not found", file=sys.stderr)
        return 1
    probe = sqlite3.connect(str(src))
    try:
        check = probe.execute("PRAGMA integrity_check").fetchone()[0]
        has_schema = probe.execute(
            "SELECT COUNT(*) FROM sqlite_master WHERE name='scan_jobs'").fetchone()[0] == 1
    except sqlite3.DatabaseError as exc:
        print(f"error: not a valid database: {exc}", file=sys.stderr)
        return 1
    finally:
        probe.close()
    if check != "ok" or not has_schema:
        print("error: source failed verification; nothing restored", file=sys.stderr)
        return 1
    target = settings.db_path
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
        # Copy the live file (with any WAL content checkpointed by sqlite) before overwriting it.
        keep = sqlite3.connect(str(target))
        try:
            dump = sqlite3.connect(str(target.with_name(f"netwatch.db.pre-restore-{stamp}")))
            try:
                keep.backup(dump)
            finally:
                dump.close()
        finally:
            keep.close()
    restored = sqlite3.connect(str(target))
    try:
        src_conn = sqlite3.connect(str(src))
        try:
            src_conn.backup(restored)
        finally:
            src_conn.close()
        # Apply any migrations newer than the backup, so an older backup still works.
        init_database(target)
    finally:
        restored.close()
    print(f"restored {src} to {target}; previous database kept as pre-restore copy")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="netwatch", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--config", help="path to TOML config (default: $NETWATCH_CONFIG or config/netwatch.toml)")
    sub = p.add_subparsers(dest="command", required=True)
    sub.add_parser("doctor")
    sub.add_parser("init-db")
    cu = sub.add_parser("create-user")
    cu.add_argument("name")
    cu.add_argument("--role", choices=["admin", "viewer"], default="admin")
    cu.add_argument("--password-stdin", action="store_true")
    rp = sub.add_parser("reset-password")
    rp.add_argument("name")
    rp.add_argument("--password-stdin", action="store_true")
    sc = sub.add_parser("scan")
    sc.add_argument("--profile", choices=["quick", "standard"], default="quick")
    sub.add_parser("scheduler")
    sub.add_parser("prune")
    sub.add_parser("serve")
    bk = sub.add_parser("backup-db")
    bk.add_argument("dest")
    rs = sub.add_parser("restore-db")
    rs.add_argument("src")
    return p


COMMANDS = {
    "doctor": cmd_doctor, "create-user": cmd_create_user, "reset-password": cmd_reset_password,
    "scan": cmd_scan, "scheduler": cmd_scheduler, "prune": cmd_prune, "serve": cmd_serve, "init-db": cmd_init_db,
    "backup-db": cmd_backup_db, "restore-db": cmd_restore_db,
}


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    settings = load_settings(args.config)
    return COMMANDS[args.command](settings, args)


if __name__ == "__main__":
    raise SystemExit(main())
