"""Tests for bounded configuration, user policy and GeoIP policy."""

from types import SimpleNamespace

import pytest

from custom_components.secure_qr_login import manager as manager_module
from custom_components.secure_qr_login.geoip import GeoIPResult
from custom_components.secure_qr_login.manager import SecureQrLoginManager


class FakeGeoIP:
    """Minimal async GeoIP resolver used by policy tests."""

    def __init__(self, result: GeoIPResult | None = None):
        self.result = result or GeoIPResult(
            "GR",
            "local_database",
            "8.8.8.8",
            "resolved",
        )

    async def async_lookup_ip(self, _ip):
        return self.result


def manager_with(options: dict, result: GeoIPResult | None = None) -> SecureQrLoginManager:
    manager = object.__new__(SecureQrLoginManager)
    manager.entry = SimpleNamespace(options=options)
    manager.geoip = FakeGeoIP(result)
    return manager


def request(remote="8.8.8.8", **headers):
    return SimpleNamespace(remote=remote, headers=headers)


def test_security_options_are_clamped_to_safe_bounds() -> None:
    manager = manager_with(
        {
            "enable_window_seconds": 9999,
            "qr_lifetime_seconds": 1,
            "max_pending_sessions": 99,
            "history_limit": 1,
        }
    )

    assert manager.enable_window_seconds == 300
    assert manager.qr_lifetime_seconds == 5
    assert manager.max_pending_sessions == 5
    assert manager.history_limit == 20


def test_empty_allowlist_allows_active_human_user() -> None:
    manager = manager_with({"allowed_user_ids": []})
    user = SimpleNamespace(id="user-1", is_active=True, system_generated=False)
    assert manager.user_allowed(user)


def test_allowlist_restricts_approval() -> None:
    manager = manager_with({"allowed_user_ids": ["allowed"]})
    allowed = SimpleNamespace(id="allowed", is_active=True, system_generated=False)
    denied = SimpleNamespace(id="denied", is_active=True, system_generated=False)
    assert manager.user_allowed(allowed)
    assert not manager.user_allowed(denied)


def test_system_and_inactive_users_are_never_allowed() -> None:
    manager = manager_with({"allowed_user_ids": []})
    assert not manager.user_allowed(
        SimpleNamespace(id="system", is_active=True, system_generated=True)
    )
    assert not manager.user_allowed(
        SimpleNamespace(id="inactive", is_active=False, system_generated=False)
    )


@pytest.mark.asyncio
async def test_country_policy_disabled_by_empty_allowlist() -> None:
    manager = manager_with({"allowed_countries": []})
    allowed, country, reason = await manager.async_country_allowed(request())
    assert allowed
    assert country == ""
    assert reason == "disabled"


@pytest.mark.asyncio
async def test_cloudflare_allowed_country() -> None:
    manager = manager_with({"allowed_countries": ["GR"]})
    allowed, country, reason = await manager.async_country_allowed(
        request(
            **{
                "CF-IPCountry": "GR",
                "CF-Ray": "abc-ATH",
                "CF-Connecting-IP": "8.8.8.8",
            }
        )
    )
    assert allowed
    assert country == "GR"
    assert reason == "cloudflare_allowed"


@pytest.mark.asyncio
async def test_cloudflare_denied_country() -> None:
    manager = manager_with({"allowed_countries": ["GR"]})
    allowed, country, reason = await manager.async_country_allowed(
        request(
            **{
                "CF-IPCountry": "US",
                "CF-Ray": "abc-IAD",
                "CF-Connecting-IP": "8.8.8.8",
            }
        )
    )
    assert not allowed
    assert country == "US"
    assert reason == "country_not_allowed"


@pytest.mark.asyncio
async def test_direct_public_ip_uses_local_geoip() -> None:
    manager = manager_with(
        {"allowed_countries": ["GR"]},
        GeoIPResult("GR", "local_database", "8.8.8.8", "resolved"),
    )
    allowed, country, reason = await manager.async_country_allowed(request())
    assert allowed
    assert country == "GR"
    assert reason == "local_geoip_allowed"


@pytest.mark.asyncio
async def test_private_network_can_bypass_when_explicitly_enabled(
    monkeypatch,
) -> None:
    monkeypatch.setattr(manager_module, "is_nabu_casa_request", lambda: False)
    manager = manager_with(
        {"allowed_countries": ["GR"], "allow_private_networks": True},
        GeoIPResult(None, "local_network", "192.168.1.50", "private_network"),
    )
    allowed, country, reason = await manager.async_country_allowed(
        request(remote="192.168.1.50")
    )
    assert allowed
    assert country == "LOCAL"
    assert reason == "private_network"


@pytest.mark.asyncio
async def test_nabu_casa_private_tunnel_ip_never_gets_lan_bypass(
    monkeypatch,
) -> None:
    monkeypatch.setattr(manager_module, "is_nabu_casa_request", lambda: True)
    manager = manager_with(
        {"allowed_countries": ["GR"], "allow_private_networks": True},
        GeoIPResult(None, "local_network", "172.30.0.5", "private_network"),
    )
    allowed, country, reason = await manager.async_country_allowed(
        request(remote="172.30.0.5")
    )
    assert not allowed
    assert country == "UNKNOWN"
    assert reason == "nabu_client_ip_unavailable"


@pytest.mark.asyncio
async def test_nabu_casa_public_client_ip_uses_local_geoip(
    monkeypatch,
) -> None:
    monkeypatch.setattr(manager_module, "is_nabu_casa_request", lambda: True)
    manager = manager_with(
        {"allowed_countries": ["GR"]},
        GeoIPResult("GR", "local_database", "8.8.8.8", "resolved"),
    )
    allowed, country, reason = await manager.async_country_allowed(request())
    assert allowed
    assert country == "GR"
    assert reason == "nabu_casa_allowed"


@pytest.mark.asyncio
async def test_cloudflare_headers_override_private_proxy_remote_ip() -> None:
    manager = manager_with(
        {"allowed_countries": ["GR"], "allow_private_networks": True},
        GeoIPResult(None, "local_network", "172.30.33.5", "private_network"),
    )
    allowed, country, reason = await manager.async_country_allowed(
        request(
            remote="172.30.33.5",
            **{
                "CF-IPCountry": "US",
                "CF-Ray": "abc-IAD",
                "CF-Connecting-IP": "8.8.8.8",
            },
        )
    )
    assert not allowed
    assert country == "US"
    assert reason == "country_not_allowed"


def test_invalid_country_codes_are_not_loaded_into_policy() -> None:
    manager = manager_with({"allowed_countries": ["GR", "ZZ", "gr"]})
    assert manager.allowed_countries == {"GR"}
