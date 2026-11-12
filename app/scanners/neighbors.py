"""Helpers that complement nmap without needing root.

* Kernel neighbour table (`ip neigh`) gives MAC addresses for hosts on directly
  attached subnets. It must NOT be used for routed networks: there the only MAC
  visible is the router's, which would be wrongly attributed to remote hosts.
* OUI vendor lookup from nmap's own mac-prefix database.
"""
from __future__ import annotations

import ipaddress
import json
import shutil
import subprocess
from functools import lru_cache
from pathlib import Path


def _run_json(args: list[str]) -> list | dict | None:
    exe = shutil.which("ip")
    if not exe:
        return None
    try:
        out = subprocess.run([exe, "-j", *args], capture_output=True, text=True, timeout=10,
                             shell=False, check=False)
        if out.returncode != 0 or not out.stdout.strip():
            return None
        return json.loads(out.stdout)
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
        return None


def local_subnets() -> list[ipaddress.IPv4Network]:
    """IPv4 subnets directly attached to this host."""
    data = _run_json(["-4", "addr", "show"]) or []
    nets: list[ipaddress.IPv4Network] = []
    for iface in data:
        for addr in iface.get("addr_info", []):
            if addr.get("family") != "inet" or "local" not in addr:
                continue
            try:
                nets.append(ipaddress.ip_interface(f"{addr['local']}/{addr['prefixlen']}").network)
            except ValueError:
                continue
    return nets


def is_local_network(cidr: str, subnets: list[ipaddress.IPv4Network] | None = None) -> bool:
    net = ipaddress.ip_network(cidr)
    subnets = local_subnets() if subnets is None else subnets
    return any(net.overlaps(s) for s in subnets)


def neighbour_macs() -> dict[str, str]:
    """Map IPv4 -> MAC for reachable/stale neighbour entries."""
    data = _run_json(["neigh", "show"]) or []
    result: dict[str, str] = {}
    for entry in data:
        ip = entry.get("dst")
        mac = (entry.get("lladdr") or "").lower()
        state = entry.get("state", [])
        states = state if isinstance(state, list) else [state]
        if not ip or not mac or any(s in ("FAILED", "INCOMPLETE") for s in states):
            continue
        if ":" not in ip:  # IPv4 only
            result[ip] = mac
    return result


def is_randomized_mac(mac: str) -> bool:
    """True when the locally-administered bit is set (typical for private/random MACs)."""
    try:
        return bool(int(mac.split(":")[0], 16) & 0x02)
    except (ValueError, IndexError):
        return False


@lru_cache(maxsize=4)
def _load_oui(path: str) -> dict[str, str]:
    table: dict[str, str] = {}
    p = Path(path)
    if not p.is_file():
        return table
    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
        parts = line.strip().split(None, 1)
        if len(parts) == 2 and len(parts[0]) == 6:
            table[parts[0].upper()] = parts[1].strip()
    return table


def vendor_for_mac(mac: str | None, oui_file: str) -> str:
    if not mac:
        return ""
    if is_randomized_mac(mac):
        return "Randomised MAC (private address)"
    prefix = mac.replace(":", "").upper()[:6]
    return _load_oui(oui_file).get(prefix, "")
