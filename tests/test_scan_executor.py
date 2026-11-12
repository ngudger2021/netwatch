"""End-to-end scan execution with nmap replaced by a stub that writes realistic XML.

No network traffic is generated: run_command is monkeypatched so nothing ever scans a live network."""
import shutil

from app.scanners.nmap_runner import RunResult
from app.services import jobs, scan_executor
from app.scanners.targets import ScanRequest
from tests.conftest import FIXTURES


def _stub(monkeypatch, fixture=None, returncode=0, timed_out=False, cancelled=False, stderr=""):
    calls = []

    def fake_run(cmd, *, timeout, stderr_path, should_cancel=lambda: False, poll_interval=0.5):
        calls.append(cmd)
        outfile = cmd[cmd.index("-oX") + 1]
        if fixture and returncode == 0:
            shutil.copy(FIXTURES / fixture, outfile)
        with open(stderr_path, "w") as fh:
            fh.write(stderr)
        return RunResult(returncode, timed_out, cancelled, stderr, 0.1)

    monkeypatch.setattr(scan_executor, "run_command", fake_run)
    monkeypatch.setattr(scan_executor, "build_command", lambda cfg, argv: ["/usr/bin/nmap", *argv])
    monkeypatch.setattr(scan_executor, "is_local_network", lambda cidr, subnets=None: False)
    return calls


def _run(conn, settings, profile, networks, **extra):
    jid = jobs.create_job(conn, ScanRequest(profile=profile, networks=tuple(networks), **extra), trigger="manual")
    job = jobs.claim_next(conn)
    status = scan_executor.execute_job(conn, settings, job)
    return jid, status


def test_standard_scan_completes_and_persists(conn, settings, monkeypatch):
    calls = _stub(monkeypatch, "nmap_standard_local.xml")
    jid, status = _run(conn, settings, "standard", ["192.168.50.0/24"])
    assert status == "completed"
    assert "--top-ports" in calls[0] and "-sT" in calls[0]
    assert calls[0][-2:] == ["--", "192.168.50.0/24"]
    assert conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0] == 3
    assert conn.execute("SELECT COUNT(*) FROM open_ports WHERE state='open'").fetchone()[0] >= 6
    types = {r[0] for r in conn.execute("SELECT type FROM events WHERE job_id=?", (jid,))}
    assert {"device_new", "port_opened", "scan_completed"} <= types
    assert conn.execute("SELECT status FROM scan_job_networks WHERE job_id=?", (jid,)).fetchone()[0] == "ok"
    # XML is deleted after ingestion to save SD card space
    assert not any(p.name.startswith(f"job{jid}-") and p.suffix == ".xml" for p in (settings.app.data_dir / "scans").iterdir())


def test_failed_nmap_marks_scan_failed_and_raises_event(conn, settings, monkeypatch):
    _stub(monkeypatch, None, returncode=1, stderr="nmap: QUITTING!")
    jid, status = _run(conn, settings, "quick", ["192.168.50.0/24"])
    assert status == "failed"
    row = conn.execute("SELECT status, error FROM scan_jobs WHERE id=?", (jid,)).fetchone()
    assert row["status"] == "failed" and "QUITTING" in row["error"]
    assert conn.execute("SELECT COUNT(*) FROM events WHERE type='scan_failed'").fetchone()[0] == 1
    # a failed scan must not mark anything offline
    assert conn.execute("SELECT COUNT(*) FROM device_observations").fetchone()[0] == 0


def test_timeout_is_reported_as_timeout(conn, settings, monkeypatch):
    _stub(monkeypatch, None, returncode=None, timed_out=True)
    _, status = _run(conn, settings, "quick", ["192.168.50.0/24"])
    assert status == "timeout"


def test_cancel_during_scan(conn, settings, monkeypatch):
    _stub(monkeypatch, None, returncode=None, cancelled=True)
    jid, status = _run(conn, settings, "quick", ["192.168.50.0/24"])
    assert status == "cancelled"


def test_partial_when_one_of_two_networks_fails(conn, settings, monkeypatch):
    calls = []

    def fake_run(cmd, *, timeout, stderr_path, should_cancel=lambda: False, poll_interval=0.5):
        calls.append(cmd)
        if "192.168.1.0/24" in cmd:
            with open(stderr_path, "w") as fh:
                fh.write("Failed to resolve")
            return RunResult(1, False, False, "Failed to resolve", 0.1)
        import shutil as sh
        sh.copy(FIXTURES / "nmap_discovery_routed.xml", cmd[cmd.index("-oX") + 1])
        return RunResult(0, False, False, "", 0.1)

    monkeypatch.setattr(scan_executor, "run_command", fake_run)
    monkeypatch.setattr(scan_executor, "build_command", lambda cfg, argv: ["/usr/bin/nmap", *argv])
    monkeypatch.setattr(scan_executor, "is_local_network", lambda cidr, subnets=None: False)
    _, status = _run(conn, settings, "quick", ["192.168.50.0/24", "192.168.1.0/24"])
    assert status == "partial"
    statuses = dict(conn.execute("SELECT cidr, status FROM scan_job_networks").fetchall())
    assert statuses == {"192.168.50.0/24": "ok", "192.168.1.0/24": "failed"}


def test_routed_network_never_gets_neighbour_macs(conn, settings, monkeypatch):
    _stub(monkeypatch, "nmap_discovery_routed.xml")
    monkeypatch.setattr(scan_executor, "neighbour_macs", lambda: {"192.168.1.10": "aa:aa:aa:aa:aa:aa"})
    _run(conn, settings, "quick", ["192.168.1.0/24"])
    assert conn.execute("SELECT COUNT(*) FROM devices WHERE mac='aa:aa:aa:aa:aa:aa'").fetchone()[0] == 0


def test_custom_target_outside_configured_network_is_rejected_before_running(conn, settings, monkeypatch):
    from app.scanners.targets import ValidationError, validate_request
    import pytest
    with pytest.raises(ValidationError):
        validate_request(ScanRequest(profile="custom", networks=(), targets=("8.8.8.8",)),
                         ["192.168.50.0/24"], 1024)
