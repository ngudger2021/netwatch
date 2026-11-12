import pytest

from app.database.connection import utc_now
from app.models import HostResult, PortResult, ScanReport
from app.services import vuln_lookup
from app.services.audit import sync_device_findings
from app.services.ingest import PortScope, ingest_unit
from tests.conftest import fixture_text


def _device_with_ports(conn, net, ports):
    job = conn.execute("INSERT INTO scan_jobs(profile, trigger, params, status, created_at) "
                       "VALUES ('standard','manual','{}','completed',?)", (utc_now(),)).lastrowid
    host = HostResult(ip="192.168.50.2", mac="30:de:4b:11:22:33", ports=ports, ports_scanned=True)
    ingest_unit(conn, job_id=job, network_id=net, report=ScanReport(hosts=[host], hosts_up=1),
                observed_at=utc_now(), ports=PortScope("top"), absence_check=False)
    return conn.execute("SELECT id FROM devices").fetchone()[0]


@pytest.mark.parametrize("product,version,expected", [
    ("OpenSSH", "7.4", "OpenSSH 7.4"),
    ("Apache httpd", "2.4.41", "Apache httpd 2.4.41"),
    ("OpenSSH", "", "OpenSSH"),
    ("", "1.0", None),
    ("nginx; rm -rf /", "1", None),
    ("$(id)", "", None),
    ("a" * 90, "", None),
    ("x|y", "1", None),
])
def test_query_builder_only_passes_safe_terms(product, version, expected):
    assert vuln_lookup.build_query(product, version) == expected


def test_parser_extracts_ids_and_cves():
    matches = vuln_lookup.parse_searchsploit_json(fixture_text("searchsploit_openssh.json"))
    assert [m.edb_id for m in matches] == ["40136", "45001"]
    assert matches[0].cves == ["CVE-2018-15473"]
    assert matches[1].cves == []


def test_parser_rejects_garbage_output():
    with pytest.raises(vuln_lookup.VulnLookupError):
        vuln_lookup.parse_searchsploit_json("not json")
    assert vuln_lookup.parse_searchsploit_json("{}") == []


def test_search_without_binary_is_clear_error(monkeypatch):
    monkeypatch.setattr(vuln_lookup, "searchsploit_path", lambda: None)
    with pytest.raises(vuln_lookup.VulnLookupError, match="exploitdb"):
        vuln_lookup.search("OpenSSH 7.4")


def test_check_device_creates_unverified_finding(conn, net_ids):
    dev = _device_with_ports(conn, net_ids["192.168.50.0/24"],
                             [PortResult(22, "tcp", "open", "ssh", "OpenSSH", "7.4")])
    matches = vuln_lookup.parse_searchsploit_json(fixture_text("searchsploit_openssh.json"))
    res = vuln_lookup.check_device(conn, dev, search_fn=lambda q: matches)
    assert res["ports_with_references"] == 1
    row = conn.execute("SELECT * FROM security_findings WHERE rule_key='exploitdb_match'").fetchone()
    assert row["severity"] == "medium" and "unverified" in row["title"]
    assert "CVE-2018-15473" in row["evidence"] and "40136" in row["evidence"]
    assert row["weight"] == 5


def test_no_matches_resolves_previous_reference(conn, net_ids):
    dev = _device_with_ports(conn, net_ids["192.168.50.0/24"],
                             [PortResult(22, "tcp", "open", "ssh", "OpenSSH", "7.4")])
    matches = vuln_lookup.parse_searchsploit_json(fixture_text("searchsploit_openssh.json"))
    vuln_lookup.check_device(conn, dev, search_fn=lambda q: matches)
    vuln_lookup.check_device(conn, dev, search_fn=lambda q: [])
    assert conn.execute("SELECT status FROM security_findings WHERE rule_key='exploitdb_match'").fetchone()[0] == "resolved"


def test_unsafe_or_empty_products_are_skipped_not_searched(conn, net_ids):
    dev = _device_with_ports(conn, net_ids["192.168.50.0/24"],
                             [PortResult(80, "tcp", "open", "http", "")])
    calls = []
    res = vuln_lookup.check_device(conn, dev, search_fn=lambda q: calls.append(q) or [])
    assert calls == [] and res["ports_checked"] == 0


def test_audit_sync_keeps_exploitdb_findings(conn, net_ids):
    dev = _device_with_ports(conn, net_ids["192.168.50.0/24"],
                             [PortResult(22, "tcp", "open", "ssh", "OpenSSH", "7.4")])
    matches = vuln_lookup.parse_searchsploit_json(fixture_text("searchsploit_openssh.json"))
    vuln_lookup.check_device(conn, dev, search_fn=lambda q: matches)
    sync_device_findings(conn, dev, "server")
    assert conn.execute("SELECT status FROM security_findings WHERE rule_key='exploitdb_match'").fetchone()[0] == "open"


def test_endpoint_refuses_without_tool_and_requires_admin(client, conn, monkeypatch):
    from app.services import vuln_lookup as vl
    monkeypatch.setattr(vl, "searchsploit_path", lambda: None)
    client.post("/api/v1/auth/login", json={"username": "admin", "password": "correct horse battery"})
    token = client.get("/api/v1/auth/me").json()["csrf_token"]
    res = client.post("/api/v1/vulnerability-checks", json={"tools": ["searchsploit"]}, headers={"X-CSRF-Token": token})
    assert res.status_code == 422 and "exploitdb" in res.text
    client.post("/api/v1/auth/logout", headers={"X-CSRF-Token": token})
    client.post("/api/v1/auth/login", json={"username": "viewer1", "password": "viewer password long"})
    assert client.post("/api/v1/vulnerability-checks", json={}).status_code in (401, 403)


def test_endpoint_runs_with_fake_tool(client, conn, net_ids, monkeypatch):
    from app.services import vuln_lookup as vl
    _device_with_ports(conn, net_ids["192.168.50.0/24"], [PortResult(22, "tcp", "open", "ssh", "OpenSSH", "7.4")])
    monkeypatch.setattr(vl, "searchsploit_path", lambda: "/fake/searchsploit")
    monkeypatch.setattr(vl, "search", lambda q, timeout=20.0: vl.parse_searchsploit_json(fixture_text("searchsploit_openssh.json")))
    client.post("/api/v1/auth/login", json={"username": "admin", "password": "correct horse battery"})
    token = client.get("/api/v1/auth/me").json()["csrf_token"]
    res = client.post("/api/v1/vulnerability-checks", json={}, headers={"X-CSRF-Token": token})
    assert res.status_code == 200 and res.json()["searchsploit"]["totals"]["ports_with_references"] == 1
    tools = client.get("/api/v1/vulnerability-tools").json()
    assert "searchsploit" in tools and tools["vulners"]["enabled"] is False and tools["nuclei"]["enabled"] is False
