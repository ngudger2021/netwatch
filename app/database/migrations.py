"""Forward-only SQL migration runner.

Files in migrations/ are applied in lexical order, each exactly once, inside a
transaction. Applied versions are recorded in schema_migrations.
"""
from __future__ import annotations

import os
import sqlite3
from pathlib import Path

MIGRATIONS_DIR = Path(os.environ.get("NETWATCH_MIGRATIONS_DIR")
                      or Path(__file__).resolve().parent.parent.parent / "migrations")


def _ensure_table(conn: sqlite3.Connection) -> None:
    conn.execute(
        "CREATE TABLE IF NOT EXISTS schema_migrations ("
        " version TEXT PRIMARY KEY, applied_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')))"
    )


def pending_migrations(conn: sqlite3.Connection, migrations_dir: Path = MIGRATIONS_DIR) -> list[Path]:
    _ensure_table(conn)
    available = sorted(migrations_dir.glob("*.sql"))
    if not available:
        raise RuntimeError(f"no migration files found in {migrations_dir}; the schema cannot be created")
    applied = {r[0] for r in conn.execute("SELECT version FROM schema_migrations")}
    return [p for p in available if p.stem not in applied]


def apply_migrations(conn: sqlite3.Connection, migrations_dir: Path = MIGRATIONS_DIR) -> list[str]:
    applied_now: list[str] = []
    for path in pending_migrations(conn, migrations_dir):
        sql = path.read_text(encoding="utf-8")
        conn.execute("BEGIN IMMEDIATE")
        try:
            for statement in _split_statements(sql):
                conn.execute(statement)
            conn.execute("INSERT INTO schema_migrations(version) VALUES (?)", (path.stem,))
            conn.execute("COMMIT")
        except BaseException:
            conn.execute("ROLLBACK")
            raise
        applied_now.append(path.stem)
    return applied_now


def _split_statements(sql: str) -> list[str]:
    """Split a migration file into statements (no triggers/procedures are used)."""
    statements: list[str] = []
    buf: list[str] = []
    for line in sql.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("--"):
            continue
        buf.append(line)
        if stripped.endswith(";"):
            statements.append("\n".join(buf).rstrip().rstrip(";"))
            buf = []
    if buf:
        raise ValueError("migration contains an unterminated statement")
    return statements
