from __future__ import annotations

import os
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"
os.environ.pop("NETWATCH_TELEGRAM_BOT_TOKEN", None)
os.environ.pop("NETWATCH_TELEGRAM_CHAT_ID", None)


def fixture_text(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


@pytest.fixture
def settings(tmp_path):
    from app.config import Settings
    return Settings.model_validate({
        "app": {"data_dir": str(tmp_path / "data"), "session_ttl_hours": 1},
        "networks": {"cidrs": ["192.168.50.0/24", "192.168.1.0/24"]},
        "scanning": {"nmap_path": "/usr/bin/nmap", "oui_file": str(tmp_path / "no-oui")},
        "change": {"offline_threshold": 3, "recent_days": 7},
    })


@pytest.fixture
def conn(settings):
    from app.database import init_database
    from app.services.bootstrap import seed_defaults
    c = init_database(settings.db_path)
    seed_defaults(c, settings)
    yield c
    c.close()


@pytest.fixture
def net_ids(conn):
    rows = conn.execute("SELECT id, cidr FROM networks").fetchall()
    return {r["cidr"]: r["id"] for r in rows}


@pytest.fixture
def make_user(conn):
    from app.database.connection import utc_now
    from app.security.auth import hash_password

    def _make(username="admin", password="correct horse battery", role="admin"):
        conn.execute("INSERT INTO users(username, password_hash, role, created_at) VALUES (?,?,?,?)",
                     (username, hash_password(password), role, utc_now()))
        return username, password
    return _make


@pytest.fixture
def client(settings, make_user, conn):
    from fastapi.testclient import TestClient
    from app.main import create_app
    app = create_app(settings)
    make_user()
    make_user("viewer1", "viewer password long", role="viewer")
    with TestClient(app, base_url="http://localhost", client=("127.0.0.1", 50000)) as c:
        yield c
