import pytest

from app.scanners.targets import (ScanRequest, ValidationError, build_nmap_args, normalise_ports,
                                  validate_request, validate_target)

CONFIGURED = ["192.168.50.0/24", "192.168.1.0/24"]


@pytest.mark.parametrize("spec,expected", [
    ("22", "22"), ("22, 80,8000-8100", "22,80,8000-8100"), ("1-1024", "1-1024"), ("", ""), (None, ""),
])
def test_port_specs_normalise(spec, expected):
    assert normalise_ports(spec) == expected


@pytest.mark.parametrize("spec", ["0", "65536", "80-22", "22;rm -rf /", "$(id)", "a-b", "1-70000", "1,,2-", ",".join(["1"] * 60)])
def test_bad_port_specs_rejected(spec):
    with pytest.raises(ValidationError):
        normalise_ports(spec)


def test_port_count_limit():
    with pytest.raises(ValidationError):
        normalise_ports("1-20000,30000-50000")


def test_target_must_be_inside_configured_network():
    assert validate_target("192.168.50.84", CONFIGURED, 1024) == "192.168.50.84/32"
    assert validate_target("192.168.1.0/28", CONFIGURED, 1024) == "192.168.1.0/28"
    with pytest.raises(ValidationError):
        validate_target("10.0.0.1", CONFIGURED, 1024)
    with pytest.raises(ValidationError):
        validate_target("192.168.0.0/23", CONFIGURED, 1024)  # wider than configured


@pytest.mark.parametrize("bad", ["192.168.50.0/24; id", "$(reboot)", "192.168.50.1 --script x", "http://x"])
def test_injection_attempts_in_targets_rejected(bad):
    with pytest.raises(ValidationError):
        validate_target(bad, CONFIGURED, 1024)


def test_host_limit_enforced():
    with pytest.raises(ValidationError):
        validate_target("192.168.0.0/16", ["192.168.0.0/16"], 1024)


def test_request_requires_something_to_scan():
    with pytest.raises(ValidationError):
        validate_request(ScanRequest(profile="quick", networks=()), CONFIGURED, 1024)


def test_concurrency_and_timeout_bounds():
    with pytest.raises(ValidationError):
        validate_request(ScanRequest(profile="custom", networks=("192.168.50.0/24",), concurrency=99), CONFIGURED, 1024)
    with pytest.raises(ValidationError):
        validate_request(ScanRequest(profile="custom", networks=("192.168.50.0/24",), host_timeout=5), CONFIGURED, 1024)


def test_unknown_profile_rejected():
    with pytest.raises(ValidationError):
        validate_request(ScanRequest(profile="aggressive", networks=("192.168.50.0/24",)), CONFIGURED, 1024)


def test_quick_profile_is_discovery_only_without_port_scan():
    args = build_nmap_args("quick", "192.168.50.0/24", outfile="/tmp/x.xml")
    assert "-sn" in args
    assert not any(a.startswith("-p") or a == "--top-ports" for a in args)
    assert "-sV" not in args


def test_standard_profile_uses_top_ports_and_light_version_detection():
    args = build_nmap_args("standard", "192.168.50.0/24", outfile="/tmp/x.xml", top_ports=100)
    assert "-sT" in args and "--top-ports" in args and "100" in args
    assert "--version-light" in args


def test_detailed_profile_uses_port_range_and_longer_timeout():
    args = build_nmap_args("detailed", "192.168.50.0/24", outfile="/tmp/x.xml", ports="1-1024",
                           host_timeout=600)
    assert args[args.index("-p") + 1] == "1-1024"
    assert "600s" in args


def test_target_is_last_after_double_dash_and_no_shell_metacharacters():
    args = build_nmap_args("standard", "192.168.50.0/24", outfile="/tmp/x.xml")
    assert args[-2:] == ["--", "192.168.50.0/24"]
    assert all(";" not in a and "|" not in a and "$(" not in a for a in args)


def test_build_rejects_non_network_target():
    with pytest.raises(ValueError):
        build_nmap_args("quick", "not-an-ip", outfile="/tmp/x.xml")


@pytest.mark.parametrize("profile", ["quick", "standard", "detailed", "custom"])
def test_unprivileged_scans_never_request_raw_sockets(profile):
    args = build_nmap_args(profile, "192.168.50.0/24", outfile="/tmp/x.xml", ports="22", privileged=False)
    assert "--unprivileged" in args


def test_privileged_quick_uses_arp_and_icmp():
    args = build_nmap_args("quick", "192.168.50.0/24", outfile="/tmp/x.xml", privileged=True)
    assert "-PE" in args and "--unprivileged" not in args
