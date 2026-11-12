from app.database.connection import utc_now
from app.models import HostResult, PortResult, ScanReport
from app.services.ingest import PortScope, ingest_unit

THRESHOLD = 3


def _job(conn, profile="standard"):
    return conn.execute("INSERT INTO scan_jobs(profile, trigger, params, status, created_at) "
                        "VALUES (?,'manual','{}','running',?)", (profile, utc_now())).lastrowid


def _scan(conn, net, hosts, *, absence=True, ports=PortScope("top"), job=None):
    job = job or _job(conn)
    report = ScanReport(hosts=hosts, hosts_up=len(hosts))
    return ingest_unit(conn, job_id=job, network_id=net, report=report, observed_at=utc_now(), ports=ports,
                       absence_check=absence, offline_threshold=THRESHOLD)


def _types(result):
    return [e["type"] for e in result.events]


def host(ip, mac="30:de:4b:11:22:33", hostname="", ports=None, scanned=False):
    return HostResult(ip=ip, mac=mac, hostname=hostname, ports=ports or [], ports_scanned=scanned)


def test_new_device_then_returning_device_events(conn, net_ids):
    n = net_ids["192.168.50.0/24"]
    r1 = _scan(conn, n, [host("192.168.50.2", hostname="win-pc")])
    assert "device_new" in _types(r1)
    # device disappears for threshold scans -> offline
    for _ in range(THRESHOLD):
        _scan(conn, n, [])
    assert conn.execute("SELECT status FROM devices").fetchone()[0] == "offline"
    r3 = _scan(conn, n, [host("192.168.50.2", hostname="win-pc")])
    assert "device_returned" in _types(r3)
    assert conn.execute("SELECT status, missing_scans FROM devices").fetchone()[0:2] == ("online", 0)


def test_offline_only_after_threshold_successful_absences(conn, net_ids):
    n = net_ids["192.168.50.0/24"]
    _scan(conn, n, [host("192.168.50.2")])
    for i in range(THRESHOLD - 1):
        res = _scan(conn, n, [])
        assert "device_offline" not in _types(res), f"offline too early at scan {i + 1}"
    assert conn.execute("SELECT status FROM devices").fetchone()[0] == "online"
    res = _scan(conn, n, [])
    assert "device_offline" in _types(res)


def test_single_missed_scan_does_not_flap_online_device(conn, net_ids):
    n = net_ids["192.168.50.0/24"]
    _scan(conn, n, [host("192.168.50.2")])
    _scan(conn, n, [])                       # one miss
    res = _scan(conn, n, [host("192.168.50.2")])
    assert "device_offline" not in _types(res) and "device_returned" not in _types(res)
    assert conn.execute("SELECT missing_scans FROM devices").fetchone()[0] == 0


def test_partial_custom_target_scan_never_counts_absence(conn, net_ids):
    n = net_ids["192.168.50.0/24"]
    _scan(conn, n, [host("192.168.50.2")])
    for _ in range(THRESHOLD + 2):
        _scan(conn, n, [], absence=False)    # narrower target: cannot conclude absence
    assert conn.execute("SELECT status, missing_scans FROM devices").fetchone()[0:2] == ("online", 0)


def test_ip_and_hostname_changes_recorded(conn, net_ids):
    n = net_ids["192.168.50.0/24"]
    _scan(conn, n, [host("192.168.50.2", hostname="old-name")])
    res = _scan(conn, n, [host("192.168.50.9", hostname="new-name")])
    types = _types(res)
    assert "ip_changed" in types and "hostname_changed" in types
    assert conn.execute("SELECT current_ip, hostname FROM devices").fetchone()[0:2] == ("192.168.50.9", "new-name")


def test_port_open_close_and_service_change(conn, net_ids):
    n = net_ids["192.168.50.0/24"]
    p22 = PortResult(22, "tcp", "open", "ssh", "OpenSSH", "8.9p1")
    p23 = PortResult(23, "tcp", "open", "telnet")
    res1 = _scan(conn, n, [host("192.168.50.1", ports=[p22, p23], scanned=True)])
    types1 = _types(res1)
    assert types1.count("port_opened") == 2
    # telnet closes, ssh version changes
    p22b = PortResult(22, "tcp", "open", "ssh", "OpenSSH", "9.6p1")
    res2 = _scan(conn, n, [host("192.168.50.1", ports=[p22b], scanned=True)])
    types2 = _types(res2)
    assert "port_closed" in types2 and "service_changed" in types2
    states = {r["port"]: r["state"] for r in conn.execute("SELECT port, state FROM open_ports")}
    assert states == {22: "open", 23: "closed"}
    # telnet comes back
    res3 = _scan(conn, n, [host("192.168.50.1", ports=[p22b, p23], scanned=True)])
    assert "port_reopened" in _types(res3)


def test_closed_port_not_concluded_when_outside_scan_scope(conn, net_ids):
    n = net_ids["192.168.50.0/24"]
    explicit = PortResult(8001, "tcp", "open", "http")
    _scan(conn, n, [host("192.168.50.84", ports=[explicit], scanned=True)],
          ports=PortScope("explicit", frozenset({8001})))
    # a standard (top-ports) scan that does not list 8001 must not report it closed
    res = _scan(conn, n, [host("192.168.50.84", ports=[], scanned=True)], ports=PortScope("top"))
    assert "port_closed" not in _types(res)


def test_quick_scan_does_not_touch_ports(conn, net_ids):
    n = net_ids["192.168.50.0/24"]
    _scan(conn, n, [host("192.168.50.1", ports=[PortResult(23, "tcp", "open", "telnet")], scanned=True)])
    res = _scan(conn, n, [host("192.168.50.1")], ports=PortScope("none"))
    assert "port_closed" not in _types(res)
    assert conn.execute("SELECT state FROM open_ports").fetchone()[0] == "open"


def test_new_risky_port_is_medium_severity_event(conn, net_ids):
    n = net_ids["192.168.50.0/24"]
    res = _scan(conn, n, [host("192.168.50.1", ports=[PortResult(23, "tcp", "open", "telnet")], scanned=True)])
    ev = next(e for e in res.events if e["type"] == "port_opened")
    assert ev["severity"] == "medium"


def test_availability_history_recorded_each_scan(conn, net_ids):
    n = net_ids["192.168.50.0/24"]
    _scan(conn, n, [host("192.168.50.2")])
    _scan(conn, n, [])
    rows = conn.execute("SELECT status FROM device_observations ORDER BY id").fetchall()
    assert [r[0] for r in rows] == ["online", "absent"]
