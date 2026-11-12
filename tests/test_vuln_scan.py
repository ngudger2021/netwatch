import pytest

from app.database.connection import utc_now
from app.models import HostResult, PortResult, ScanReport
from app.scanners import nmap_parser
from app.scanners.nmap_runner import RunResult
from app.services import vuln_runner, vuln_scan
from app.services.ingest import PortScope, ingest_unit
from tests.conftest import fixture_text


# ---------- defaults and safety ------------------------------------------------
def test_both_tools_disabled_by_default(settings):
    assert settings.vulnerability.vulners_enabled is False
    assert settings.vulnerability.nuclei_enabled is False


def test_vulners_refused_when_disabled(conn, settings):
    with pytest.raises(vuln_runner.VulnRunRefused, match="vulners_enabled"):
        vuln_runner.validate_request(settings, ["vulners"], conn)


def test_nuclei_refused_when_disabled(conn, settings):
    with pytest.raises(vuln_runner.VulnRunRefused, match="nuclei_enabled"):
        vuln_runner.validate_request(settings, ["nuclei"], conn)


def test_unknown_tool_refused(conn, settings):
    with pytest.raises(vuln_runner.VulnRunRefused):
        vuln_runner.validate_request(settings, ["metasploit"], conn)


def test_refused_while_scan_active(conn, settings):
    from app.scanners.targets import ScanRequest
    from app.services import jobs
    settings.vulnerability.vulners_enabled = True
    jobs.create_job(conn, ScanRequest(profile="quick", networks=("192.168.50.0/24",)), trigger="manual")
    with pytest.raises(vuln_runner.VulnRunRefused, match="scan is queued"):
        vuln_runner.validate_request(settings, ["vulners"], conn)


def test_vulners_argv_is_fixed_and_validated():
    args = vuln_scan.build_vulners_args("192.168.50.1", "22,80", "/tmp/x.xml")
    assert args[args.index("--script") + 1] == "vulners"
    assert args[args.index("-p") + 1] == "22,80"
    assert args[-2:] == ["--", "192.168.50.1"]
    assert args.count("--script") == 1 and "*" not in " ".join(args)
    with pytest.raises(ValueError):
        vuln_scan.build_vulners_args("192.168.50.1; id", "22", "/tmp/x.xml")
    with pytest.raises(ValueError):
        vuln_scan.build_vulners_args("192.168.50.1", "", "/tmp/x.xml")
    with pytest.raises(Exception):
        vuln_scan.build_vulners_args("192.168.50.1", "22;reboot", "/tmp/x.xml")


def test_nuclei_argv_excludes_intrusive_and_disables_callbacks():
    args = vuln_scan.build_nuclei_args("/tmp/t.txt", "/tmp/o.jsonl")
    tags = args[args.index("-tags") + 1].split(",")
    excluded = args[args.index("-exclude-tags") + 1].split(",")
    assert set(tags) == {"exposure", "misconfig", "tech", "panel"}
    assert {"dos", "fuzz", "intrusive", "brute-force", "default-login"} <= set(excluded)
    assert "-ni" in args and "-duc" in args
    assert args[args.index("-rl") + 1] == "5" and args[args.index("-c") + 1] == "3"


# ---------- parsers ----------------------------------------------------------------
def test_vulners_output_parsed_highest_first():
    report = nmap_parser.parse_nmap_xml(fixture_text("nmap_vulners.xml"), ports_scanned=True)
    output = report.hosts[0].ports[0].scripts["vulners"]
    cves = vuln_scan.parse_vulners_output(output)
    assert cves[0] == ("CVE-2021-41617", 7.0)
    assert [c for c, _ in cves] == ["CVE-2021-41617", "CVE-2018-15473", "CVE-2016-6210"]


@pytest.mark.parametrize("score,sev", [(9.8, "critical"), (7.0, "high"), (5.0, "medium"), (2.1, "low")])
def test_cvss_bands(score, sev):
    assert vuln_scan.cvss_severity(score) == sev


def test_nuclei_parser_skips_bad_lines_and_normalises_severity():
    hits = vuln_scan.parse_nuclei_jsonl(fixture_text("nuclei_output.jsonl"))
    assert len(hits) == 3
    assert hits[2]["severity"] == "high" and hits[2]["template"] == "git-config-exposed"
    assert vuln_scan.parse_nuclei_jsonl('{"info":{"severity":"weird"}}')[0]["severity"] == "info"


def test_web_urls_built_only_for_web_services():
    assert vuln_scan.build_urls("192.168.50.1", 80, "http", "micro_httpd") == "http://192.168.50.1:80/"
    assert vuln_scan.build_urls("192.168.50.1", 443, "https", "") == "https://192.168.50.1:443/"
    assert vuln_scan.build_urls("192.168.50.1", 22, "ssh", "OpenSSH") is None
    assert vuln_scan.build_urls("192.168.50.1", 99999, "http", "") is None


# ---------- end to end with stubbed tools --------------------------------------
def _device(conn, net, ports):
    job = conn.execute("INSERT INTO scan_jobs(profile, trigger, params, status, created_at) "
                       "VALUES ('standard','manual','{}','completed',?)", (utc_now(),)).lastrowid
    host = HostResult(ip="192.168.50.1", mac="30:de:4b:11:22:33", ports=ports, ports_scanned=True)
    ingest_unit(conn, job_id=job, network_id=net, report=ScanReport(hosts=[host], hosts_up=1),
                observed_at=utc_now(), ports=PortScope("top"), absence_check=False)
    return conn.execute("SELECT id FROM devices").fetchone()[0]


def test_vulners_run_stores_cve_findings(conn, settings, net_ids, monkeypatch, tmp_path):
    dev = _device(conn, net_ids["192.168.50.0/24"], [PortResult(22, "tcp", "open", "ssh", "OpenSSH", "7.4"),
                                                      PortResult(80, "tcp", "open", "http", "micro_httpd")])
    scans = tmp_path / "scans"
    scans.mkdir()

    def fake_run(cmd, *, timeout, stderr_path, should_cancel=lambda: False, poll_interval=0.5):
        (scans / f"vulners-{dev}.xml").write_text(fixture_text("nmap_vulners.xml"))
        return RunResult(0, False, False, "", 0.1)

    monkeypatch.setattr(vuln_scan, "run_command", fake_run)
    monkeypatch.setattr(vuln_scan, "build_command", lambda cfg, argv: ["/usr/bin/nmap", *argv])
    specs = vuln_scan.load_devices(conn, [dev])
    res = vuln_scan.run_vulners(conn, settings, specs, scans)
    assert res["ports_with_cves"] == 1
    row = conn.execute("SELECT * FROM security_findings WHERE rule_key='vulners_cve'").fetchone()
    assert row["port"] == 22 and row["severity"] == "high"  # top CVSS 7.0
    assert "CVE-2018-15473" in row["evidence"] and "unverified" in row["title"]


def test_nuclei_run_matches_per_exact_port(conn, settings, net_ids, monkeypatch, tmp_path):
    dev = _device(conn, net_ids["192.168.50.0/24"], [PortResult(80, "tcp", "open", "http", "micro_httpd"),
                                                      PortResult(8080, "tcp", "open", "http", "proxy")])
    scans = tmp_path / "scans"
    scans.mkdir()

    def fake_run(cmd, *, timeout, stderr_path, should_cancel=lambda: False, poll_interval=0.5):
        out = cmd[cmd.index("-o") + 1]
        with open(out, "w") as fh:
            fh.write(fixture_text("nuclei_output.jsonl"))
        return RunResult(0, False, False, "", 0.1)

    monkeypatch.setattr(vuln_scan, "run_command", fake_run)
    specs = vuln_scan.load_devices(conn, [dev])
    res = vuln_scan.run_nuclei(conn, settings, specs, scans, "/fake/nuclei")
    assert res["urls"] == 2
    rows = {r["port"]: r for r in conn.execute("SELECT * FROM security_findings WHERE rule_key='nuclei_match'")}
    assert set(rows) == {80, 8080}                    # 'tech' info hit on 80 is kept as info; panel is medium
    assert rows[80]["severity"] == "medium" and "router-admin-panel" in rows[80]["evidence"]
    assert "tech-detect" in rows[80]["evidence"]
    assert rows[8080]["severity"] == "high" and "git-config-exposed" in rows[8080]["evidence"]
    assert "git-config-exposed" not in rows[80]["evidence"]   # port 8080 result must not leak onto port 80


def test_missing_nuclei_is_reported_clearly(conn, settings, monkeypatch):
    settings.vulnerability.nuclei_enabled = True
    monkeypatch.setattr(vuln_scan, "nuclei_path", lambda: None)
    monkeypatch.setattr(vuln_runner, "validate_request", lambda *a, **k: None)
    monkeypatch.setattr(vuln_runner.threading, "Thread", type("T", (), {"__init__": lambda s, **k: None,
                                                                         "start": lambda s: vuln_runner._run(
                                                                             settings, ["nuclei"], None)}))
    vuln_runner.start(settings, ["nuclei"], None, conn=conn)
    status = vuln_runner.read_status(conn)
    assert status["state"] == "error" and "nuclei is not installed" in status["error"]


def test_status_roundtrip(conn):
    vuln_runner._write_status(conn, state="done", result={"x": 1})
    assert vuln_runner.read_status(conn)["state"] == "done"


def test_endpoint_status_and_refusal(client, conn):
    client.post("/api/v1/auth/login", json={"username": "admin", "password": "correct horse battery"})
    token = client.get("/api/v1/auth/me").json()["csrf_token"]
    res = client.post("/api/v1/vulnerability-checks", json={"tools": ["nuclei"]}, headers={"X-CSRF-Token": token})
    assert res.status_code == 422 and "nuclei_enabled" in res.text
    assert client.get("/api/v1/vulnerability-checks/status").json()["state"] == "idle"
    tools = client.get("/api/v1/vulnerability-tools").json()
    assert tools["nuclei"]["enabled"] is False and tools["vulners"]["enabled"] is False


def test_background_run_success_records_done_status(conn, settings, monkeypatch):
    settings.vulnerability.vulners_enabled = True
    monkeypatch.setattr(vuln_scan, "vulners_script_installed", lambda path: True)
    monkeypatch.setattr(vuln_scan, "run_vulners", lambda c, s, specs, scans: {"devices_checked": len(specs), "ports_with_cves": 0})
    vuln_runner._write_status(conn, state="running", tools=["vulners"])
    vuln_runner._run(settings, ["vulners"], None)
    status = vuln_runner.read_status(conn)
    assert status["state"] == "done" and status["result"]["vulners"]["devices_checked"] == 0
    assert status["finished"]


def test_background_run_refused_lock_is_reported(conn, settings, monkeypatch):
    from app.services import jobs
    settings.vulnerability.vulners_enabled = True
    with jobs.runner_lock(settings.scan_lock_path) as held:
        assert held is True
        vuln_runner._run(settings, ["vulners"], None)
    status = vuln_runner.read_status(conn)
    assert status["state"] == "error" and "runner lock" in status["error"]
