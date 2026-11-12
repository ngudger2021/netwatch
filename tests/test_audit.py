from app.database.connection import utc_now
from app.models import HostResult, PortResult, ScanReport
from app.services.audit import compute_score, evaluate_open_ports, risk_level, sync_device_findings
from app.services.ingest import PortScope, ingest_unit


def _port_rows(conn, device_id):
    return conn.execute("SELECT * FROM open_ports WHERE device_id=? AND state='open'", (device_id,)).fetchall()


def _ingest(conn, net, hosts):
    job = conn.execute("INSERT INTO scan_jobs(profile, trigger, params, status, created_at) "
                       "VALUES ('standard','manual','{}','running',?)", (utc_now(),)).lastrowid
    ingest_unit(conn, job_id=job, network_id=net, report=ScanReport(hosts=hosts, hosts_up=len(hosts)),
                observed_at=utc_now(), ports=PortScope("top"), absence_check=False)


def _host(ip, ports, mac="30:de:4b:11:22:33", hostname=""):
    return HostResult(ip=ip, mac=mac, hostname=hostname, ports=ports, ports_scanned=True)


def test_telnet_and_ftp_findings_with_evidence(conn, net_ids):
    _ingest(conn, net_ids["192.168.50.0/24"], [_host("192.168.50.5", [
        PortResult(23, "tcp", "open", "telnet"), PortResult(21, "tcp", "open", "ftp", "vsftpd", "3.0.3")])])
    findings = evaluate_open_ports(1, "server", _port_rows(conn, 1))
    keys = {f.rule_key for f in findings}
    assert {"telnet", "ftp_plain"} <= keys
    telnet = next(f for f in findings if f.rule_key == "telnet")
    assert telnet.severity == "high" and "23/tcp open" in telnet.evidence
    assert telnet.remediation


def test_ssh_is_informational_and_carries_no_weight(conn, net_ids):
    _ingest(conn, net_ids["192.168.50.0/24"], [_host("192.168.50.2", [PortResult(22, "tcp", "open", "ssh", "OpenSSH")])])
    findings = evaluate_open_ports(1, "workstation", _port_rows(conn, 1))
    assert [f.severity for f in findings] == ["info"]
    score, explanation = compute_score(findings)
    assert score == 0 and explanation == []


def test_database_and_vnc_exposure(conn, net_ids):
    _ingest(conn, net_ids["192.168.50.0/24"], [_host("192.168.50.9", [
        PortResult(3306, "tcp", "open", "mysql"), PortResult(5900, "tcp", "open", "vnc")])])
    keys = {f.rule_key for f in evaluate_open_ports(1, "server", _port_rows(conn, 1))}
    assert {"db_exposed", "vnc_exposed"} <= keys


def test_smbv1_requires_positive_script_evidence(conn, net_ids):
    p = PortResult(445, "tcp", "open", "microsoft-ds")
    _ingest(conn, net_ids["192.168.50.0/24"], [_host("192.168.50.2", [p])])
    assert "smbv1" not in {f.rule_key for f in evaluate_open_ports(1, "workstation", _port_rows(conn, 1))}
    # Now with script output positively identifying SMBv1
    conn.execute("UPDATE open_ports SET script_output = 'smb-protocols: dialects: NT LM 0.12 (SMBv1)' WHERE port=445")
    assert "smbv1" in {f.rule_key for f in evaluate_open_ports(1, "workstation", _port_rows(conn, 1))}


def test_plain_http_is_flagged_but_https_is_not(conn, net_ids):
    _ingest(conn, net_ids["192.168.50.0/24"], [_host("192.168.50.5", [
        PortResult(80, "tcp", "open", "http", "micro_httpd"), PortResult(443, "tcp", "open", "https")])])
    rows = _port_rows(conn, 1)
    keys = [(f.rule_key, f.port) for f in evaluate_open_ports(1, "server-mgmt", rows)]
    assert ("http_plain_mgmt", 80) in keys
    assert not any(p == 443 for _, p in keys)


def test_findings_persist_resolve_and_reopen(conn, net_ids):
    _ingest(conn, net_ids["192.168.50.0/24"], [_host("192.168.50.5", [PortResult(23, "tcp", "open", "telnet")])])
    assert conn.execute("SELECT COUNT(*) FROM security_findings WHERE status='open'").fetchone()[0] == 1
    # re-syncing unchanged evidence is idempotent: no duplicate events
    assert sync_device_findings(conn, 1, "server") == []
    # telnet disappears from the device
    conn.execute("UPDATE open_ports SET state='closed' WHERE port=23")
    ev2 = sync_device_findings(conn, 1, "server")
    assert [e["type"] for e in ev2] == ["finding_resolved"]
    assert conn.execute("SELECT status FROM security_findings").fetchone()[0] == "resolved"
    # and comes back
    conn.execute("UPDATE open_ports SET state='open' WHERE port=23")
    ev3 = sync_device_findings(conn, 1, "server")
    assert [e["type"] for e in ev3] == ["finding_new"]
    assert conn.execute("SELECT status FROM security_findings").fetchone()[0] == "open"


def test_score_is_sum_of_weights_when_under_cap(conn, net_ids):
    ports = [PortResult(p, "tcp", "open", s) for p, s in [(23, "telnet"), (21, "ftp"), (3306, "mysql"),
                                                           (5900, "vnc"), (3389, "ms-wbt-server"), (623, "asf-rmcp")]]
    _ingest(conn, net_ids["192.168.50.0/24"], [_host("192.168.50.5", ports)])
    score = conn.execute("SELECT risk_score FROM devices WHERE id=1").fetchone()[0]
    # telnet 25 + ftp 10 + db 20 + vnc 20 + rdp 10 + ipmi 10
    assert score == 95


def test_score_is_capped_at_100(conn, net_ids):
    ports = [PortResult(p, "tcp", "open", s) for p, s in [(23, "telnet"), (21, "ftp"), (3306, "mysql"),
                                                           (5900, "vnc"), (3389, "ms-wbt-server"), (623, "asf-rmcp"),
                                                           (445, "microsoft-ds")]]
    host = _host("192.168.50.5", ports)
    host.ports[-1].scripts = {"smb-protocols": "dialects: SMBv1"}
    _ingest(conn, net_ids["192.168.50.0/24"], [host])
    findings = evaluate_open_ports(1, "server", _port_rows(conn, 1))
    assert sum(f.weight for f in findings) > 100
    assert conn.execute("SELECT risk_score FROM devices WHERE id=1").fetchone()[0] == 100


def test_trusted_device_keeps_same_score_and_findings(conn, net_ids):
    _ingest(conn, net_ids["192.168.50.0/24"], [_host("192.168.50.5", [PortResult(23, "tcp", "open", "telnet")])])
    sync_device_findings(conn, 1, "server")
    before = conn.execute("SELECT risk_score FROM devices WHERE id=1").fetchone()[0]
    conn.execute("UPDATE devices SET trusted=1 WHERE id=1")
    sync_device_findings(conn, 1, "server")
    after = conn.execute("SELECT risk_score FROM devices WHERE id=1").fetchone()[0]
    assert before == after == 25
    assert conn.execute("SELECT COUNT(*) FROM security_findings WHERE status='open'").fetchone()[0] == 1


def test_risk_levels():
    assert risk_level(0) == "low" and risk_level(30) == "medium" and risk_level(80) == "high"
