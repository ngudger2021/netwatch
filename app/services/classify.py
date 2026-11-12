"""Heuristic device-type classification from vendor, hostname and open ports.

The result is a hint only; users can override it (device_type_source='user').
"""
from __future__ import annotations

import re

_RULES: list[tuple[str, re.Pattern]] = [
    ("router", re.compile(r"asus|tp-?link|netgear|ubiquiti|mikrotik|router|linksys|d-link|eero", re.I)),
    ("media", re.compile(r"samsung|tizen|sonos|roku|chromecast|lg electronics|sony|apple tv|bravia", re.I)),
    ("smart-home", re.compile(r"meross|tuya|shelly|espressif|philips hue|sonoff|wemo", re.I)),
    ("camera", re.compile(r"hikvision|dahua|axis comm|septekon|reolink|camera", re.I)),
    ("server-mgmt", re.compile(r"\bilo\b|idrac|ipmi|supermicro", re.I)),
    ("single-board", re.compile(r"raspberry", re.I)),
]
_PORT_TYPES = [
    ({9100, 631}, "printer"),
    ({554}, "camera"),
    ({623}, "server-mgmt"),
    ({3389}, "workstation"),
]


def classify_device(ip: str, vendor: str, hostname: str, ports: set[int], product_text: str = "") -> str:
    text = " ".join([vendor or "", hostname or "", product_text or ""])
    for kind, pattern in _RULES:
        if pattern.search(text):
            return kind
    for port_set, kind in _PORT_TYPES:
        if ports & port_set:
            return kind
    if ip.endswith(".1"):
        return "router"
    if 22 in ports and not (ports & {3389, 445}):
        return "server"
    if ports & {445, 135}:
        return "workstation"
    return "unknown"
