import pytest

from app.scanners.targets import ScanRequest
from app.services import jobs

REQ = ScanRequest(profile="quick", networks=("192.168.50.0/24",))


def test_create_and_claim_job(conn):
    jid = jobs.create_job(conn, REQ, trigger="manual", requested_by="tester")
    row = jobs.claim_next(conn)
    assert row["id"] == jid and row["status"] == "running" and row["started_at"]


def test_only_one_active_job_allowed(conn):
    jobs.create_job(conn, REQ, trigger="manual")
    with pytest.raises(jobs.ActiveJobError):
        jobs.create_job(conn, REQ, trigger="schedule")


def test_cancel_queued_job_immediately(conn):
    jid = jobs.create_job(conn, REQ, trigger="manual")
    assert jobs.request_cancel(conn, jid) == "cancelled"
    assert conn.execute("SELECT status FROM scan_jobs WHERE id=?", (jid,)).fetchone()[0] == "cancelled"
    jobs.create_job(conn, REQ, trigger="manual")  # slot is free again


def test_cancel_running_job_sets_flag(conn):
    jid = jobs.create_job(conn, REQ, trigger="manual")
    jobs.claim_next(conn)
    assert jobs.request_cancel(conn, jid) == "cancel-requested"
    assert jobs.cancel_requested(conn, jid)


def test_unknown_job_cancel_raises(conn):
    with pytest.raises(KeyError):
        jobs.request_cancel(conn, 9999)


def test_interrupted_running_jobs_are_marked_failed(conn):
    jid = jobs.create_job(conn, REQ, trigger="manual")
    jobs.claim_next(conn)
    assert jobs.recover_interrupted(conn) == 1
    row = conn.execute("SELECT status, error FROM scan_jobs WHERE id=?", (jid,)).fetchone()
    assert row["status"] == "failed" and "interrupted" in row["error"]


def test_runner_lock_is_exclusive(tmp_path):
    lock = tmp_path / "scan.lock"
    with jobs.runner_lock(lock) as first:
        assert first is True
        with jobs.runner_lock(lock) as second:
            assert second is False
    with jobs.runner_lock(lock) as again:
        assert again is True


def test_finish_records_duration(conn):
    jid = jobs.create_job(conn, REQ, trigger="manual")
    jobs.claim_next(conn)
    jobs.finish(conn, jid, "completed", hosts_up=3, hosts_total=256)
    row = conn.execute("SELECT status, duration_seconds, hosts_up FROM scan_jobs WHERE id=?", (jid,)).fetchone()
    assert row["status"] == "completed" and row["duration_seconds"] >= 0 and row["hosts_up"] == 3
