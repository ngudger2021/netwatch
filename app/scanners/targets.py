"""Validation of scan targets, port specifications and scan profiles.

Everything that reaches the nmap argument list passes through these functions
first. Targets must be inside a configured network; port specs are strictly
numeric.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

PROFILES = ("quick", "standard", "detailed", "custom")
_PORT_ITEM = re.compile(r"^(\d{1,5})(?:-(\d{1,5}))?$")
MAX_PORT_ITEMS = 50
MAX_PORT_COUNT = 10000


class ValidationError(ValueError):
    pass


@dataclass(frozen=True)
class ScanRequest:
    profile: str
    networks: tuple[str, ...]          # configured CIDRs to scan (subset of configured networks)
    targets: tuple[str, ...] = ()       # optional narrower targets (IP or CIDR inside a network)
    ports: str = ""                     # normalised port spec; '' = profile default
    concurrency: int | None = None      # custom profile only
    host_timeout: int | None = None     # seconds, custom profile only
    service_detection: bool = True      # custom profile only


def normalise_ports(spec: str | None, max_port_count: int = MAX_PORT_COUNT) -> str:
    """Return a canonical port spec such as '22,80,8000-8100' or raise ValidationError."""
    if spec is None or not str(spec).strip():
        return ""
    items = [i.strip() for i in str(spec).split(",") if i.strip()]
    if not items or len(items) > MAX_PORT_ITEMS:
        raise ValidationError("port specification must contain 1-50 entries")
    out: list[str] = []
    total = 0
    for item in items:
        m = _PORT_ITEM.match(item)
        if not m:
            raise ValidationError(f"invalid port entry: {item!r}")
        lo = int(m.group(1))
        hi = int(m.group(2)) if m.group(2) else lo
        if not (1 <= lo <= 65535 and 1 <= hi <= 65535):
            raise ValidationError(f"port out of range: {item!r}")
        if lo > hi:
            raise ValidationError(f"port range is reversed: {item!r}")
        total += hi - lo + 1
        out.append(str(lo) if lo == hi else f"{lo}-{hi}")
    if total > max_port_count:
        raise ValidationError(f"too many ports requested ({total} > {max_port_count})")
    return ",".join(out)


def validate_profile(profile: str) -> str:
    if profile not in PROFILES:
        raise ValidationError(f"unknown scan profile: {profile!r}")
    return profile


def validate_target(target: str, configured: list[str], max_hosts: int) -> str:
    """Accept an IPv4 address or CIDR that lies wholly inside a configured network."""
    try:
        if "/" in target:
            net = ipaddress.ip_network(target, strict=False)
        else:
            net = ipaddress.ip_network(f"{ipaddress.ip_address(target)}/32")
    except ValueError as exc:
        raise ValidationError(f"invalid target {target!r}: {exc}") from exc
    if net.version != 4:
        raise ValidationError("only IPv4 targets are supported")
    if net.num_addresses > max_hosts:
        raise ValidationError(f"target {target} exceeds the {max_hosts}-host limit")
    for cidr in configured:
        parent = ipaddress.ip_network(cidr)
        if net.subnet_of(parent):
            return str(net)
    raise ValidationError(f"target {target} is outside the configured networks")


def validate_request(req: ScanRequest, configured: list[str], max_hosts: int) -> ScanRequest:
    validate_profile(req.profile)
    if not req.networks and not req.targets:
        raise ValidationError("select at least one network or target")
    nets = tuple(validate_target(n, configured, max_hosts) for n in req.networks)
    targs = tuple(validate_target(t, configured, max_hosts) for t in req.targets)
    ports = normalise_ports(req.ports)
    conc = req.concurrency
    if conc is not None and not (1 <= conc <= 64):
        raise ValidationError("concurrency must be between 1 and 64")
    timeout = req.host_timeout
    if timeout is not None and not (30 <= timeout <= 3600):
        raise ValidationError("host timeout must be between 30 and 3600 seconds")
    return ScanRequest(
        profile=req.profile, networks=nets, targets=targs, ports=ports,
        concurrency=conc, host_timeout=timeout, service_detection=bool(req.service_detection),
    )


def build_nmap_args(
    profile: str,
    target: str,
    *,
    outfile: str,
    ports: str = "",
    top_ports: int = 100,
    default_detailed_ports: str = "1-1024",
    privileged: bool = False,
    parallelism: int = 16,
    host_timeout: int = 300,
    service_detection: bool = True,
) -> list[str]:
    """Return the argument vector (without the nmap binary) for one target.

    The target is appended last after '--' so it can never be parsed as an option.
    """
    validate_profile(profile)
    ipaddress.ip_network(target, strict=False)  # defensive: raises if not an address/CIDR
    args: list[str] = ["-oX", outfile, "--max-retries", "2",
                       "--max-parallelism", str(parallelism),
                       "--host-timeout", f"{host_timeout}s"]
    discovery_ports = "22,80,443,445,3389,8080"
    if not privileged:
        # Without raw sockets nmap would try ARP discovery on directly attached subnets and quit
        # ("Couldn't open a raw socket"). --unprivileged makes it use TCP connect probes instead.
        args += ["--unprivileged"]
    if profile == "quick":
        args += ["-sn"]
        if privileged:
            args += ["-PE", f"-PS{discovery_ports}", "-PA80,443", "-PP"]
        else:
            args += [f"-PS{discovery_ports}", "-PA80,443"]
    elif profile == "standard":
        args += ["-sT", "--top-ports", str(top_ports)]
        if service_detection:
            args += ["-sV", "--version-light"]
    elif profile == "detailed":
        args += ["-sT", "-p", ports or default_detailed_ports, "-sV", "--version-intensity", "5"]
    elif profile == "custom":
        args += ["-sT"]
        args += ["-p", ports] if ports else ["--top-ports", str(top_ports)]
        if service_detection:
            args += ["-sV", "--version-light"]
    args += ["--", target]
    return args
