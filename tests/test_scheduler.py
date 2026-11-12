from datetime import datetime, timedelta, timezone

from app.database.connection import utc_now
from app.services import jobs
from app.services.bootstrap import set_setting
from app.services.scheduler import Scheduler


def _scheduler(settings, monkeypatch):
    s = Scheduler(settings)
    return s


def test_first_tick_enqueues_quick_discovery_over_enabled_networks(settings, monkeypatch):
    s = _scheduler(settings, monkeypatch)
    s.enqueue_due()
    row = s.conn.execute("SELECT profile, trigger, params, status FROM scan_jobs").fetchone()
    assert row["profile"] == "quick" and row["trigger"] == "schedule" and row["status"] == "queued"
    assert "192.168.50.0/24" in row["params"] and "192.168.1.0/24" in row["params"]


def test_disabled_network_is_excluded_from_schedule(settings):
    s = _scheduler(settings, None)
    s.conn.execute("UPDATE networks SET enabled=0 WHERE cidr='192.168.1.0/24'")
    s.enqueue_due()
    params = s.conn.execute("SELECT params FROM scan_jobs").fetchone()[0]
    assert "192.168.1.0/24" not in params


def test_schedule_does_not_duplicate_within_interval(settings):
    s = _scheduler(settings, None)
    s.enqueue_due()
    jobs.claim_next(s.conn)
    jobs.finish(s.conn, 1, "completed")
    s.enqueue_due()  # quick interval (15 min) not elapsed: no second discovery job
    assert s.conn.execute("SELECT COUNT(*) FROM scan_jobs WHERE profile='quick'").fetchone()[0] == 1
    # the first standard scan is queued once the discovery job has finished
    assert s.conn.execute("SELECT COUNT(*) FROM scan_jobs WHERE profile='standard'").fetchone()[0] == 1


def test_schedule_skipped_while_another_job_active(settings):
    s = _scheduler(settings, None)
    from app.scanners.targets import ScanRequest
    jobs.create_job(s.conn, ScanRequest(profile="detailed", networks=("192.168.50.0/24",)), trigger="manual")
    s.enqueue_due()
    assert s.conn.execute("SELECT COUNT(*) FROM scan_jobs").fetchone()[0] == 1


def test_due_check_respects_elapsed_time(settings):
    s = _scheduler(settings, None)
    old = (datetime.now(timezone.utc) - timedelta(minutes=16)).strftime("%Y-%m-%dT%H:%M:%SZ")
    set_setting(s.conn, "sched_last:quick", old)
    s.enqueue_due()
    assert s.conn.execute("SELECT COUNT(*) FROM scan_jobs WHERE profile='quick'").fetchone()[0] == 1


def test_retention_prunes_only_old_history(settings):
    s = _scheduler(settings, None)
    old = "2000-01-01T00:00:00Z"
    s.conn.execute("INSERT INTO events(created_at, type, severity, title) VALUES (?,'x','info','old')", (old,))
    s.conn.execute("INSERT INTO events(created_at, type, severity, title) VALUES (?,'x','info','new')", (utc_now(),))
    removed = s.prune_history()
    titles = [r[0] for r in s.conn.execute("SELECT title FROM events")]
    assert titles == ["new"] and removed["events"] == 1


def test_error_is_reported_as_app_error_event(settings):
    s = _scheduler(settings, None)
    s._report_app_error(RuntimeError("disk on fire at https://api.telegram.org/bot1:SECRET"))
    row = s.conn.execute("SELECT type, severity, title FROM events WHERE type='app_error'").fetchone()
    assert row["severity"] == "high" and "SECRET" not in row["title"]


def test_recover_interrupted_on_startup(settings):
    s = _scheduler(settings, None)
    from app.scanners.targets import ScanRequest
    jobs.create_job(s.conn, ScanRequest(profile="quick", networks=("192.168.50.0/24",)), trigger="manual")
    jobs.claim_next(s.conn)
    assert jobs.recover_interrupted(s.conn) == 1


def test_backup_and_restore_roundtrip(settings, tmp_path, conn, monkeypatch):
    from app.cli import main
    conn.execute("INSERT INTO app_settings(key,value,updated_at) VALUES ('marker','keep-me',?)", (utc_now(),))
    backup = tmp_path / "bk" / "netwatch.db"
    monkeypatch.setenv("NETWATCH_DATA_DIR", str(settings.app.data_dir))
    cfg = tmp_path / "cfg.toml"
    cfg.write_text(f'[app]\ndata_dir = "{settings.app.data_dir}"\n')
    assert main(["--config", str(cfg), "backup-db", str(backup)]) == 0
    assert backup.exists() and (backup.stat().st_mode & 0o777) == 0o600
    conn.execute("DELETE FROM app_settings WHERE key='marker'")
    assert main(["--config", str(cfg), "restore-db", str(backup)]) == 0
    from app.database import connect
    c = connect(settings.db_path)
    assert c.execute("SELECT value FROM app_settings WHERE key='marker'").fetchone()[0] == "keep-me"


def test_restore_rejects_non_database(settings, tmp_path):
    from app.cli import main
    bogus = tmp_path / "bogus.db"
    bogus.write_text("this is not sqlite")
    cfg = tmp_path / "cfg.toml"
    cfg.write_text(f'[app]\ndata_dir = "{settings.app.data_dir}"\n')
    assert main(["--config", str(cfg), "restore-db", str(bogus)]) == 1
