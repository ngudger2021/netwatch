"""Parse nmap XML (-oX) output into ScanReport objects.

Only the subset of the schema NetWatch needs is read. Anything unexpected is
ignored rather than raising, but a document that is not nmap XML at all is an
error so that a failed scan is never mistaken for an empty network.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET

from app.models import HostResult, PortResult, ScanReport


class NmapParseError(ValueError):
    pass


def parse_nmap_xml(xml_text: str, ports_scanned: bool = False) -> ScanReport:
    if not xml_text or not xml_text.strip():
        raise NmapParseError("empty nmap output")
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise NmapParseError(f"malformed nmap XML: {exc}") from exc
    if root.tag != "nmaprun":
        raise NmapParseError("root element is not nmaprun")

    report = ScanReport()
    for host_el in root.findall("host"):
        host = _parse_host(host_el, ports_scanned)
        if host is None:
            continue
        report.hosts.append(host)

    up = [h for h in report.hosts if h.state == "up"]
    report.hosts = up
    report.hosts_up = len(up)

    finished = root.find("runstats/finished")
    hosts_el = root.find("runstats/hosts")
    if finished is not None:
        try:
            report.elapsed_seconds = float(finished.get("elapsed", "0") or 0)
        except ValueError:
            report.elapsed_seconds = 0.0
        report.summary = finished.get("summary", "")
    if hosts_el is not None:
        try:
            report.hosts_total = int(hosts_el.get("total", "0") or 0)
        except ValueError:
            report.hosts_total = len(report.hosts)
    else:
        report.hosts_total = len(report.hosts)
    return report


def _parse_host(el: ET.Element, ports_scanned: bool) -> HostResult | None:
    status = el.find("status")
    state = status.get("state", "unknown") if status is not None else "unknown"

    ipv4 = None
    mac = None
    vendor = ""
    for addr in el.findall("address"):
        kind = addr.get("addrtype")
        if kind == "ipv4" and ipv4 is None:
            ipv4 = addr.get("addr")
        elif kind == "mac":
            mac = (addr.get("addr") or "").lower() or None
            vendor = addr.get("vendor", "") or ""
    if not ipv4:
        return None  # IPv6-only or malformed host entries are skipped

    hostname = ""
    for hn in el.findall("hostnames/hostname"):
        if hn.get("type") in (None, "PTR", "user"):
            hostname = hn.get("name", "") or ""
            break

    host = HostResult(ip=ipv4, state=state, mac=mac, vendor=vendor, hostname=hostname,
                      ports_scanned=ports_scanned)

    for port_el in el.findall("ports/port"):
        port = _parse_port(port_el)
        if port is not None:
            host.ports.append(port)
    return host


def _parse_port(el: ET.Element) -> PortResult | None:
    try:
        portid = int(el.get("portid", ""))
    except ValueError:
        return None
    state_el = el.find("state")
    state = state_el.get("state", "unknown") if state_el is not None else "unknown"
    svc = el.find("service")
    scripts = {s.get("id", ""): (s.get("output") or "") for s in el.findall("script")}
    return PortResult(
        port=portid,
        protocol=el.get("protocol", "tcp"),
        state=state,
        service=(svc.get("name", "") if svc is not None else "") or "",
        product=(svc.get("product", "") if svc is not None else "") or "",
        version=(svc.get("version", "") if svc is not None else "") or "",
        extrainfo=(svc.get("extrainfo", "") if svc is not None else "") or "",
        scripts=scripts,
    )
