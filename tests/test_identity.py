from app.database.connection import utc_now
from app.services.identity import Observation, normalise_mac, resolve_device
from app.services.ingest import ingest_unit, PortScope
from app.models import HostResult, ScanReport


def _insert_device(conn, net_id, *, mac=None, ip="192.168.50.20", hostname="", vendor="", randomized=0, last_seen=None):
    now = utc_now()
    cur = conn.execute(
        """INSERT INTO devices(mac, mac_randomized, hostname, vendor, network_id, current_ip, status,
           first_seen, last_seen, created_at, updated_at) VALUES (?,?,?,?,?,?,'online',?,?,?,?)""",
        (mac, randomized, hostname, vendor, net_id, ip, now, last_seen or now, now, now))
    return cur.lastrowid


def obs(ip="192.168.50.20", mac=None, hostname="", vendor="", net=1):
    return Observation(ip=ip, network_id=net, observed_at=utc_now(), mac=mac, hostname=hostname, vendor=vendor)


def test_normalise_mac():
    assert normalise_mac("AA-BB-CC-DD-EE-FF") == "aa:bb:cc:dd:ee:ff"
    assert normalise_mac("nonsense") is None
    assert normalise_mac(None) is None


def test_same_mac_is_same_device_even_when_ip_changed(conn, net_ids):
    dev = _insert_device(conn, net_ids["192.168.50.0/24"], mac="30:de:4b:11:22:33", ip="192.168.50.20")
    res = resolve_device(conn, obs(ip="192.168.50.77", mac="30:de:4b:11:22:33"), set(), 7)
    assert res.device_id == dev and res.reason == "mac" and not res.created


def test_device_with_different_real_mac_is_never_a_candidate(conn, net_ids):
    n = net_ids["192.168.50.0/24"]
    _insert_device(conn, n, mac="30:de:4b:11:22:33", ip="192.168.50.20", hostname="printer")
    # Same IP, same hostname, same vendor, but a different *real* MAC: a different device.
    res = resolve_device(conn, obs(ip="192.168.50.20", mac="9c:8e:99:aa:bb:cc", hostname="printer",
                                   vendor="HP"), set(), 7)
    assert res.created


def test_macless_device_adopts_learned_mac_when_corroborated(conn, net_ids):
    n = net_ids["192.168.50.0/24"]
    dev = _insert_device(conn, n, mac=None, ip="192.168.50.20", hostname="printer")
    # Non-root scans often lack MACs; once a MAC is learned for the same IP+hostname it is the same device.
    res = resolve_device(conn, obs(ip="192.168.50.20", mac="9c:8e:99:aa:bb:cc", hostname="printer"), set(), 7)
    assert res.device_id == dev and res.reason == "heuristic"


def test_hostname_and_network_alone_do_not_merge(conn, net_ids):
    n = net_ids["192.168.50.0/24"]
    _insert_device(conn, n, mac=None, ip="192.168.50.20", hostname="android")
    res = resolve_device(conn, obs(ip="192.168.50.99", mac="9c:8e:99:aa:bb:cc", hostname="android"), set(), 7)
    assert res.created  # score 40 (hostname) only -> below threshold


def test_hostname_network_and_vendor_merge_randomised_device(conn, net_ids):
    n = net_ids["192.168.50.0/24"]
    dev = _insert_device(conn, n, mac="2a:4d:5e:6f:70:81", ip="192.168.50.30", hostname="pixel",
                         vendor="Randomised MAC (private address)", randomized=1)
    # Phone rotated its random MAC and got a new IP; hostname, vendor and recency corroborate.
    res = resolve_device(conn, obs(ip="192.168.50.44", mac="2a:99:88:77:66:55", hostname="pixel",
                                   vendor="Randomised MAC (private address)"), set(), 7)
    assert res.device_id == dev and res.reason == "heuristic" and res.score >= 70


def test_already_matched_device_in_same_scan_is_not_reused(conn, net_ids):
    n = net_ids["192.168.50.0/24"]
    dev = _insert_device(conn, n, mac=None, ip="192.168.50.20")
    res = resolve_device(conn, obs(ip="192.168.50.20"), {dev}, 7)
    assert res.created


def test_macless_observation_matches_same_ip_device(conn, net_ids):
    n = net_ids["192.168.50.0/24"]
    dev = _insert_device(conn, n, mac=None, ip="192.168.50.20")
    res = resolve_device(conn, obs(ip="192.168.50.20"), set(), 7)
    assert res.device_id == dev and res.reason == "ip-anchored"


def test_macless_observation_on_other_ip_creates_device(conn, net_ids):
    n = net_ids["192.168.50.0/24"]
    _insert_device(conn, n, mac=None, ip="192.168.50.20", hostname="x")
    assert resolve_device(conn, obs(ip="192.168.50.99"), set(), 7).created


def test_same_ip_on_different_network_does_not_match(conn, net_ids):
    _insert_device(conn, net_ids["192.168.50.0/24"], mac=None, ip="192.168.1.10")
    res = resolve_device(conn, obs(ip="192.168.1.10", net=net_ids["192.168.1.0/24"]), set(), 7)
    assert res.created


def test_ingest_keeps_identity_and_address_separate(conn, net_ids):
    n = net_ids["192.168.50.0/24"]
    job = conn.execute("INSERT INTO scan_jobs(profile, trigger, params, status, created_at) "
                       "VALUES ('standard','manual','{}','running',?)", (utc_now(),)).lastrowid
    first = ScanReport(hosts=[HostResult(ip="192.168.50.20", mac="30:de:4b:11:22:33", hostname="laptop")], hosts_up=1)
    second = ScanReport(hosts=[HostResult(ip="192.168.50.88", mac="30:de:4b:11:22:33", hostname="laptop")], hosts_up=1)
    ingest_unit(conn, job_id=job, network_id=n, report=first, observed_at=utc_now(), ports=PortScope("none"),
                absence_check=True)
    ingest_unit(conn, job_id=job, network_id=n, report=second, observed_at=utc_now(), ports=PortScope("none"),
                absence_check=True)
    devices = conn.execute("SELECT * FROM devices").fetchall()
    assert len(devices) == 1 and devices[0]["current_ip"] == "192.168.50.88"
    addrs = {r["ip"] for r in conn.execute("SELECT ip FROM device_addresses WHERE device_id=?", (devices[0]["id"],))}
    assert addrs == {"192.168.50.20", "192.168.50.88"}
