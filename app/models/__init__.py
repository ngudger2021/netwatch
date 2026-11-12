"""Plain data structures passed between scanners and services."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class PortResult:
    port: int
    protocol: str
    state: str                  # open | closed | filtered | open|filtered ...
    service: str = ""
    product: str = ""
    version: str = ""
    extrainfo: str = ""
    scripts: dict[str, str] = field(default_factory=dict)


@dataclass
class HostResult:
    ip: str
    state: str = "up"
    mac: str | None = None
    vendor: str = ""
    hostname: str = ""
    ports: list[PortResult] = field(default_factory=list)
    ports_scanned: bool = False


@dataclass
class ScanReport:
    hosts: list[HostResult] = field(default_factory=list)
    hosts_up: int = 0
    hosts_total: int = 0
    elapsed_seconds: float = 0.0
    summary: str = ""
