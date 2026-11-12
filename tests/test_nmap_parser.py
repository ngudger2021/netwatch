import pytest

from app.scanners.nmap_parser import NmapParseError, parse_nmap_xml
from tests.conftest import fixture_text


def test_routed_discovery_parses_hosts_and_stats():
    r = parse_nmap_xml(fixture_text("nmap_discovery_routed.xml"), ports_scanned=False)
    assert [h.ip for h in r.hosts] == ["192.168.1.10", "192.168.1.11"]
    assert r.hosts_up == 2 and r.hosts_total == 256
    assert r.hosts[0].hostname == "nas.lan"
    assert r.hosts[0].mac is None          # routed: no MAC visible in nmap output
    assert r.hosts[0].ports == [] and r.hosts[0].ports_scanned is False


def test_standard_scan_extracts_ports_services_and_mac_vendor():
    r = parse_nmap_xml(fixture_text("nmap_standard_local.xml"), ports_scanned=True)
    router = next(h for h in r.hosts if h.ip == "192.168.50.1")
    assert router.mac == "30:de:4b:11:22:33"
    assert router.vendor == "ASUSTek COMPUTER INC."
    assert router.hostname == "router.lan"
    ports = {p.port: p for p in router.ports}
    assert set(ports) == {22, 23, 80, 443}
    assert ports[22].service == "ssh" and ports[22].product == "OpenSSH"
    assert ports[22].version == "8.9p1 Ubuntu"
    assert ports[23].service == "telnet" and ports[23].state == "open"
    assert router.ports_scanned is True


def test_down_hosts_are_excluded_and_ipv6_entries_ignored():
    r = parse_nmap_xml(fixture_text("nmap_standard_local.xml"), ports_scanned=True)
    assert all(h.state == "up" for h in r.hosts)
    assert "192.168.50.200" not in [h.ip for h in r.hosts]
    assert r.hosts_up == 3


def test_randomised_mac_is_preserved_for_identity_logic():
    r = parse_nmap_xml(fixture_text("nmap_standard_local.xml"), ports_scanned=True)
    tv = next(h for h in r.hosts if h.ip == "192.168.50.84")
    assert tv.mac == "2a:4d:5e:6f:70:81"
    assert tv.vendor == ""


@pytest.mark.parametrize("payload", ["", "   ", "<html>not nmap</html>", "{not xml", "Failed to resolve host"])
def test_invalid_output_raises(payload):
    with pytest.raises(NmapParseError):
        parse_nmap_xml(payload)


def test_failed_scan_text_never_parses_as_empty_network():
    with pytest.raises(NmapParseError):
        parse_nmap_xml(fixture_text("nmap_error.txt"))
