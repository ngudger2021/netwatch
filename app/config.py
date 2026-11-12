"""Configuration loading and validation.

Settings come from a TOML file (default: config/netwatch.toml, override with
NETWATCH_CONFIG). Secrets (Telegram token/chat) are read from the environment
only and never written to the database or logs.
"""
from __future__ import annotations

import ipaddress
import os
import tomllib
from pathlib import Path

from pydantic import BaseModel, Field, field_validator, model_validator

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def validate_cidr(value: str) -> str:
    try:
        net = ipaddress.ip_network(value.strip(), strict=True)
    except ValueError as exc:
        raise ValueError(f"invalid network '{value}': {exc}") from exc
    if net.version != 4:
        raise ValueError(f"only IPv4 networks are supported: {value}")
    if net.prefixlen < 16 or net.prefixlen > 30:
        raise ValueError(f"network {value} must be between /16 and /30")
    if net.is_loopback or net.is_multicast or net.is_unspecified:
        raise ValueError(f"network {value} is not a valid scan target")
    return str(net)


class AppConfig(BaseModel):
    data_dir: Path = PROJECT_ROOT / "data"
    bind_host: str = "127.0.0.1"
    bind_port: int = Field(8787, ge=1, le=65535)
    session_ttl_hours: int = Field(12, ge=1, le=168)
    secure_cookies: bool = False
    history_retention_days: int = Field(180, ge=7, le=3650)

    @field_validator("bind_host")
    @classmethod
    def _host(cls, v: str) -> str:
        ipaddress.ip_address(v)  # must be an IP literal; hostnames not accepted
        return v


class NetworksConfig(BaseModel):
    cidrs: list[str] = Field(default_factory=lambda: ["192.168.50.0/24", "192.168.1.0/24"])

    @field_validator("cidrs")
    @classmethod
    def _validate(cls, values: list[str]) -> list[str]:
        if not values:
            raise ValueError("at least one network must be configured")
        cleaned = [validate_cidr(v) for v in values]
        if len(set(cleaned)) != len(cleaned):
            raise ValueError("duplicate networks configured")
        return cleaned


class ScanningConfig(BaseModel):
    nmap_path: str = "/usr/bin/nmap"
    privileged: bool = False            # True only if nmap is granted root via sudoers (see README)
    use_sudo: bool = False
    max_hosts_per_target: int = Field(1024, ge=1, le=65536)
    job_timeout_seconds: int = Field(3600, ge=60, le=86400)
    host_timeout_seconds: int = Field(300, ge=30, le=3600)
    max_parallelism: int = Field(16, ge=1, le=64)
    nice_level: int = Field(10, ge=0, le=19)
    top_ports: int = Field(100, ge=10, le=1000)
    default_detailed_ports: str = "1-1024"
    oui_file: str = "/usr/share/nmap/nmap-mac-prefixes"

    @field_validator("nmap_path")
    @classmethod
    def _nmap(cls, v: str) -> str:
        if not os.path.isabs(v):
            raise ValueError("nmap_path must be an absolute path")
        return v


class ScheduleConfig(BaseModel):
    enabled: bool = True
    discovery_minutes: int = Field(15, ge=5, le=1440)
    standard_hours: int = Field(6, ge=1, le=168)
    summary_hours: int = Field(24, ge=1, le=168)


class ChangeConfig(BaseModel):
    offline_threshold: int = Field(3, ge=1, le=20)   # successful scans absent before 'offline'
    recent_days: int = Field(7, ge=1, le=90)


class TelegramConfig(BaseModel):
    enabled: bool = False
    cooldown_seconds: int = Field(900, ge=0, le=86400)
    daily_summary: bool = True
    # Secrets come from the environment: NETWATCH_TELEGRAM_BOT_TOKEN, NETWATCH_TELEGRAM_CHAT_ID


class Settings(BaseModel):
    app: AppConfig = Field(default_factory=AppConfig)
    networks: NetworksConfig = Field(default_factory=NetworksConfig)
    scanning: ScanningConfig = Field(default_factory=ScanningConfig)
    schedule: ScheduleConfig = Field(default_factory=ScheduleConfig)
    change: ChangeConfig = Field(default_factory=ChangeConfig)
    telegram: TelegramConfig = Field(default_factory=TelegramConfig)

    @model_validator(mode="after")
    def _cross_checks(self) -> "Settings":
        if self.scanning.privileged and not self.scanning.use_sudo:
            # Privileged discovery needs root; without sudo the process must itself be root,
            # which the service is designed to avoid.
            raise ValueError("scanning.privileged requires scanning.use_sudo = true")
        return self

    @property
    def db_path(self) -> Path:
        return Path(self.app.data_dir) / "netwatch.db"

    @property
    def scan_lock_path(self) -> Path:
        return Path(self.app.data_dir) / "scan.lock"


def load_settings(path: str | os.PathLike | None = None) -> Settings:
    cfg_path = Path(path or os.environ.get("NETWATCH_CONFIG", PROJECT_ROOT / "config" / "netwatch.toml"))
    raw: dict = {}
    if cfg_path.exists():
        with cfg_path.open("rb") as fh:
            raw = tomllib.load(fh)
    settings = Settings.model_validate(raw)
    if os.environ.get("NETWATCH_DATA_DIR"):
        settings.app.data_dir = Path(os.environ["NETWATCH_DATA_DIR"])
    return settings


def telegram_credentials() -> tuple[str, str] | None:
    token = os.environ.get("NETWATCH_TELEGRAM_BOT_TOKEN", "").strip()
    chat = os.environ.get("NETWATCH_TELEGRAM_CHAT_ID", "").strip()
    return (token, chat) if token and chat else None
