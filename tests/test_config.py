import pytest
from pydantic import ValidationError

from app.config import Settings, load_settings


def test_example_config_loads():
    s = load_settings("config/netwatch.example.toml")
    assert s.networks.cidrs == ["192.168.50.0/24", "192.168.1.0/24"]
    assert s.schedule.discovery_minutes == 15 and s.schedule.standard_hours == 6


@pytest.mark.parametrize("bad", ["10.0.0.0/8", "192.168.50.5/24", "not-a-net", "::/64", "127.0.0.0/24", "0.0.0.0/0"])
def test_invalid_networks_rejected(bad):
    with pytest.raises(ValidationError):
        Settings.model_validate({"networks": {"cidrs": [bad]}})


def test_duplicate_networks_rejected():
    with pytest.raises(ValidationError):
        Settings.model_validate({"networks": {"cidrs": ["192.168.50.0/24", "192.168.50.0/24"]}})


def test_bind_host_must_be_ip_literal():
    with pytest.raises(ValidationError):
        Settings.model_validate({"app": {"bind_host": "localhost"}})


def test_privileged_requires_sudo():
    with pytest.raises(ValidationError):
        Settings.model_validate({"scanning": {"privileged": True, "use_sudo": False}})


def test_nmap_path_must_be_absolute():
    with pytest.raises(ValidationError):
        Settings.model_validate({"scanning": {"nmap_path": "nmap"}})


def test_telegram_secrets_are_not_config_fields():
    s = Settings()
    assert "bot_token" not in s.telegram.model_dump()
    assert "chat_id" not in s.telegram.model_dump()
