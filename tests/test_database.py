import sqlite3

import pytest

from app.database import connect, init_database, transaction
from app.database.migrations import apply_migrations, pending_migrations


def test_migrations_apply_once(tmp_path):
    db = tmp_path / "x.db"
    conn = init_database(db)
    assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    assert pending_migrations(conn) == []
    assert apply_migrations(conn) == []          # idempotent
    versions = [r[0] for r in conn.execute("SELECT version FROM schema_migrations")]
    assert versions == ["001_initial"]


def test_expected_tables_exist(conn):
    names = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    for table in ["networks", "devices", "device_addresses", "scan_jobs", "scan_results", "device_observations",
                  "open_ports", "service_observations", "security_findings", "events", "alert_rules",
                  "notification_history", "app_settings", "users", "sessions", "audit_log"]:
        assert table in names, table


def test_transaction_rolls_back_on_error(conn):
    with pytest.raises(RuntimeError):
        with transaction(conn):
            conn.execute("INSERT INTO app_settings(key, value, updated_at) VALUES ('k','v','now')")
            raise RuntimeError("boom")
    assert conn.execute("SELECT COUNT(*) FROM app_settings WHERE key='k'").fetchone()[0] == 0


def test_foreign_key_enforced(conn):
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("INSERT INTO open_ports(device_id, port, state, first_seen, last_seen) "
                     "VALUES (999, 22, 'open', 'x', 'x')")


def test_bad_migration_is_rolled_back(tmp_path):
    mig = tmp_path / "migs"
    mig.mkdir()
    (mig / "001_bad.sql").write_text("CREATE TABLE ok_table (id INTEGER);\nCREATE TABLE ok_table (id INTEGER);\n")
    conn = connect(tmp_path / "b.db")
    with pytest.raises(sqlite3.OperationalError):
        apply_migrations(conn, mig)
    assert conn.execute("SELECT COUNT(*) FROM sqlite_master WHERE name='ok_table'").fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM schema_migrations").fetchone()[0] == 0


def test_migrations_directory_is_found_and_empty_dir_is_an_error(tmp_path):
    from app.database.migrations import MIGRATIONS_DIR
    assert any(MIGRATIONS_DIR.glob("*.sql")), "migrations directory must contain the schema"
    conn = connect(tmp_path / "e.db")
    with pytest.raises(RuntimeError):
        pending_migrations(conn, tmp_path / "missing")
