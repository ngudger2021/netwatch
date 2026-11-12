import json

from app.database.connection import utc_now
from app.models import HostResult, PortResult, ScanReport
from app.services.ingest import PortScope, ingest_unit


def login(client, username, password):
    res = client.post("/api/v1/auth/login", json={"username": username, "password": password})
    return res


def admin_client(client):
    res = login(client, "admin", "correct horse battery")
    assert res.status_code == 200, res.text
    return res.json()["csrf_token"]


def seed_inventory(conn):
    net = conn.execute("SELECT id FROM networks WHERE cidr='192.168.50.0/24'").fetchone()[0]
    job = conn.execute("INSERT INTO scan_jobs(profile, trigger, params, status, created_at) "
                       "VALUES ('standard','manual','{}','completed',?)", (utc_now(),)).lastrowid
    hosts = [
        HostResult(ip="192.168.50.1", mac="30:de:4b:11:22:33", hostname="router.lan", ports_scanned=True,
                   ports=[PortResult(23, "tcp", "open", "telnet"), PortResult(80, "tcp", "open", "http", "micro_httpd")]),
        HostResult(ip="192.168.50.5", mac="9c:8e:99:aa:bb:cc", vendor="Hewlett Packard", ports_scanned=True,
                   ports=[PortResult(443, "tcp", "open", "https", "HP iLO"), PortResult(5900, "tcp", "open", "vnc")]),
        HostResult(ip="192.168.50.84", mac="2a:4d:5e:6f:70:81", ports_scanned=False),
    ]
    ingest_unit(conn, job_id=job, network_id=net, report=ScanReport(hosts=hosts, hosts_up=3),
                observed_at=utc_now(), ports=PortScope("top"), absence_check=True)
    return net


def test_health_is_public_and_minimal(client):
    res = client.get("/api/v1/health")
    assert res.status_code == 200 and res.json()["status"] == "ok"
    assert set(res.json()) == {"status", "time"}


def test_api_requires_authentication(client):
    assert client.get("/api/v1/devices").status_code == 401
    assert client.get("/api/v1/dashboard").status_code == 401
    assert client.get("/api/v1/system").status_code == 401


def test_pages_redirect_to_login_when_signed_out(client):
    res = client.get("/devices", follow_redirects=False)
    assert res.status_code == 303 and res.headers["location"] == "/login"


def test_login_sets_hardened_cookie(client):
    res = login(client, "admin", "correct horse battery")
    cookie = res.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie and "netwatch_session=" in cookie
    assert "secure" not in cookie  # secure_cookies is off in test settings


def test_wrong_password_and_unknown_user_look_identical(client):
    a = login(client, "admin", "wrong password here")
    b = login(client, "nobody", "wrong password here")
    assert a.status_code == b.status_code == 401
    assert a.json() == b.json()


def test_login_rate_limit_returns_429(client):
    for _ in range(5):
        login(client, "admin", "wrong password here")
    res = login(client, "admin", "correct horse battery")
    assert res.status_code == 429 and "Retry-After" in res.headers


def test_cross_origin_login_refused(client):
    res = client.post("/api/v1/auth/login", json={"username": "admin", "password": "correct horse battery"},
                      headers={"Origin": "https://evil.example"})
    assert res.status_code == 403


def test_viewer_can_read_but_not_change(client, conn):
    seed_inventory(conn)
    login(client, "viewer1", "viewer password long")
    assert client.get("/api/v1/devices").status_code == 200
    assert client.post("/api/v1/scans", json={"profile": "quick", "networks": ["192.168.50.0/24"]}).status_code == 403
    assert client.get("/api/v1/audit").status_code == 403


def test_state_change_requires_csrf_token(client, conn):
    seed_inventory(conn)
    token = admin_client(client)
    no_token = client.patch("/api/v1/devices/1", json={"trusted": True})
    assert no_token.status_code == 403
    bad = client.patch("/api/v1/devices/1", json={"trusted": True}, headers={"X-CSRF-Token": "forged"})
    assert bad.status_code == 403
    ok = client.patch("/api/v1/devices/1", json={"trusted": True}, headers={"X-CSRF-Token": token})
    assert ok.status_code == 200 and ok.json()["trusted"] is True


def test_device_list_filters_sorting_and_pagination(client, conn):
    seed_inventory(conn)
    login(client, "viewer1", "viewer password long")
    data = client.get("/api/v1/devices", params={"size": 2}).json()
    assert data["total"] == 3 and len(data["items"]) == 2 and data["pages"] == 2
    assert [d["ip"] for d in data["items"]] == ["192.168.50.1", "192.168.50.5"]  # numeric IP ordering
    page2 = client.get("/api/v1/devices", params={"size": 2, "page": 2}).json()
    assert [d["ip"] for d in page2["items"]] == ["192.168.50.84"]
    medium = client.get("/api/v1/devices", params={"risk": "medium"}).json()
    assert [d["ip"] for d in medium["items"]] == ["192.168.50.1"]      # telnet (25) + plain HTTP (4) = 29
    assert client.get("/api/v1/devices", params={"risk": "high"}).json()["total"] == 0
    q = client.get("/api/v1/devices", params={"q": "Hewlett"}).json()
    assert q["total"] == 1 and q["items"][0]["ip"] == "192.168.50.5"
    desc = client.get("/api/v1/devices", params={"sort": "ip", "order": "desc"}).json()
    assert desc["items"][0]["ip"] == "192.168.50.84"


def test_invalid_filter_values_rejected(client, conn):
    login(client, "viewer1", "viewer password long")
    assert client.get("/api/v1/devices", params={"status": "bogus"}).status_code == 422
    assert client.get("/api/v1/devices", params={"size": 5000}).status_code == 422
    assert client.get("/api/v1/devices", params={"sort": "ip", "order": "sideways"}).status_code == 422


def test_device_detail_contains_identity_findings_and_explanation(client, conn):
    seed_inventory(conn)
    login(client, "viewer1", "viewer password long")
    d = client.get("/api/v1/devices/1").json()
    assert d["mac"] == "30:de:4b:11:22:33" and d["vendor"] == ""
    assert any(f["rule_key"] == "telnet" for f in d["findings"])
    assert d["risk_score"] == 29                                   # telnet 25 + plain HTTP 4
    assert d["risk_explanation"][0]["title"] == "Telnet service exposed"
    assert d["risk_explanation"][0]["weight"] == 25
    assert client.get("/api/v1/devices/9999").status_code == 404


def test_random_mac_flagged_in_detail(client, conn):
    seed_inventory(conn)
    login(client, "viewer1", "viewer password long")
    d = client.get("/api/v1/devices/3").json()
    assert d["mac_randomized"] is True


def test_device_update_validation(client, conn):
    seed_inventory(conn)
    token = admin_client(client)
    h = {"X-CSRF-Token": token}
    assert client.patch("/api/v1/devices/1", json={"device_type": "toaster"}, headers=h).status_code == 422
    assert client.patch("/api/v1/devices/1", json={"notes": "x" * 5000}, headers=h).status_code == 422
    assert client.patch("/api/v1/devices/1", json={}, headers=h).status_code == 422
    res = client.patch("/api/v1/devices/1", json={"custom_name": "Core router", "device_type": "router"}, headers=h)
    assert res.json()["custom_name"] == "Core router"
    assert conn.execute("SELECT device_type_source FROM devices WHERE id=1").fetchone()[0] == "user"


def test_scan_creation_validates_scope_and_ports(client, conn):
    seed_inventory(conn)
    token = admin_client(client)
    h = {"X-CSRF-Token": token}
    outside = client.post("/api/v1/scans", json={"profile": "custom", "targets": ["8.8.8.8"]}, headers=h)
    assert outside.status_code == 422 and "outside" in outside.text
    inj = client.post("/api/v1/scans", json={"profile": "detailed", "networks": ["192.168.50.0/24"],
                                             "ports": "22;id"}, headers=h)
    assert inj.status_code == 422
    wrong = client.post("/api/v1/scans", json={"profile": "standard", "networks": ["192.168.50.0/24"],
                                               "ports": "22"}, headers=h)
    assert wrong.status_code == 422


def test_scan_queue_and_overlap_protection(client, conn):
    seed_inventory(conn)
    token = admin_client(client)
    h = {"X-CSRF-Token": token}
    first = client.post("/api/v1/scans", json={"profile": "quick", "networks": ["192.168.50.0/24"]}, headers=h)
    assert first.status_code == 202 and first.json()["status"] == "queued"
    second = client.post("/api/v1/scans", json={"profile": "quick", "networks": ["192.168.50.0/24"]}, headers=h)
    assert second.status_code == 409
    jid = first.json()["job_id"]
    cancel = client.post(f"/api/v1/scans/{jid}/cancel", headers=h)
    assert cancel.status_code == 200 and cancel.json()["result"] == "cancelled"


def test_findings_endpoint_and_acknowledge(client, conn):
    seed_inventory(conn)
    token = admin_client(client)
    findings = client.get("/api/v1/findings", params={"status": "open"}).json()
    assert findings["total"] >= 2
    fid = findings["items"][0]["id"]
    res = client.post(f"/api/v1/findings/{fid}/acknowledge", headers={"X-CSRF-Token": token})
    assert res.status_code == 200
    assert client.get("/api/v1/findings", params={"status": "acknowledged"}).json()["total"] == 1


def test_events_and_dashboard(client, conn):
    seed_inventory(conn)
    login(client, "viewer1", "viewer password long")
    ev = client.get("/api/v1/events").json()
    assert ev["total"] > 0 and all("title" in e for e in ev["items"])
    dash = client.get("/api/v1/dashboard").json()
    assert dash["stats"]["devices_total"] == 3 and dash["stats"]["online"] == 3
    assert {"online_vs_offline", "devices_per_subnet", "availability", "new_discoveries",
            "ports_by_service", "findings_by_severity"} <= set(dash["charts"])
    assert dash["activity"]


def test_settings_and_network_management(client, conn):
    token = admin_client(client)
    h = {"X-CSRF-Token": token}
    s = client.get("/api/v1/settings").json()
    assert s["telegram"]["credentials_present"] is False
    assert "bot_token" not in json.dumps(s).lower()
    assert client.post("/api/v1/networks", json={"cidr": "10.0.0.0/8"}, headers=h).status_code == 422
    created = client.post("/api/v1/networks", json={"cidr": "172.16.0.0/24", "name": "lab"}, headers=h)
    assert created.status_code == 201
    dup = client.post("/api/v1/networks", json={"cidr": "172.16.0.0/24"}, headers=h)
    assert dup.status_code == 409
    rules = client.get("/api/v1/settings").json()["alert_rules"]
    rules[0]["min_severity"] = "critical"
    res = client.put("/api/v1/settings/alert-rules", json={"rules": rules}, headers=h)
    assert res.status_code == 200


def test_telegram_test_needs_credentials(client, conn):
    token = admin_client(client)
    res = client.post("/api/v1/notifications/test", headers={"X-CSRF-Token": token})
    assert res.status_code == 422 and "credentials" in res.text


def test_reports_download_in_all_formats(client, conn):
    seed_inventory(conn)
    login(client, "viewer1", "viewer password long")
    csv_res = client.get("/api/v1/reports/inventory/csv")
    assert csv_res.status_code == 200 and csv_res.headers["content-type"].startswith("text/csv")
    assert "192.168.50.5" in csv_res.text and "attachment" in csv_res.headers["content-disposition"]
    js = client.get("/api/v1/reports/findings/json").json()
    assert js["dataset"] == "findings" and js["count"] >= 1
    html_res = client.get("/api/v1/reports/ports/html")
    assert html_res.status_code == 200 and "<table>" in html_res.text
    assert client.get("/api/v1/reports/secrets/csv").status_code == 404
    assert client.get("/api/v1/reports/inventory/exe").status_code == 404


def test_reports_never_contain_password_hashes(client, conn):
    seed_inventory(conn)
    login(client, "viewer1", "viewer password long")
    for name in ["inventory", "ports", "findings", "changes", "statistics"]:
        assert "scrypt$" not in client.get(f"/api/v1/reports/{name}/json").text


def test_security_headers_present(client):
    res = client.get("/api/v1/health")
    assert res.headers["x-frame-options"] == "DENY"
    assert res.headers["x-content-type-options"] == "nosniff"
    assert "frame-ancestors 'none'" in res.headers["content-security-policy"]
    assert res.headers["cache-control"] == "no-store"


def test_logout_revokes_session(client, conn):
    token = admin_client(client)
    assert client.get("/api/v1/devices").status_code == 200
    client.post("/api/v1/auth/logout", headers={"X-CSRF-Token": token})
    assert client.get("/api/v1/devices").status_code == 401


def test_openapi_documentation_served(client):
    res = client.get("/api/openapi.json")
    assert res.status_code == 200
    paths = res.json()["paths"]
    assert "/api/v1/devices" in paths and "/api/v1/scans" in paths and "/api/v1/reports/{dataset}/{fmt}" in paths
    assert client.get("/api/docs").status_code == 200


def test_pages_render_for_signed_in_admin(client, conn):
    admin_client(client)
    for path in ["/", "/devices", "/scans", "/findings", "/events", "/reports", "/settings", "/system"]:
        res = client.get(path)
        assert res.status_code == 200, path
        assert 'data-page="' in res.text
        assert "Content-Security-Policy" in res.headers
