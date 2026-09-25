"""Tests for bounded configuration, user policy and GeoIP policy."""

from types import SimpleNamespace

from custom_components.secure_qr_login.manager import SecureQrLoginManager


def manager_with(options: dict) -> SecureQrLoginManager:
    manager = object.__new__(SecureQrLoginManager)
    manager.entry = SimpleNamespace(options=options)
    return manager


def request(remote="198.51.100.10", **headers):
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


def test_country_policy_disabled_by_empty_allowlist() -> None:
    manager = manager_with({"allowed_countries": []})

    allowed, country, reason = manager.country_allowed(request())
    assert allowed
    assert country == ""
    assert reason == "disabled"


def test_cloudflare_allowed_country() -> None:
    manager = manager_with({"allowed_countries": ["GR"]})

    allowed, country, reason = manager.country_allowed(
        request(
            **{
                "CF-IPCountry": "GR",
                "CF-Ray": "abc-ATH",
                "CF-Connecting-IP": "198.51.100.10",
            }
        )
    )

    assert allowed
    assert country == "GR"
    assert reason == "allowed"


def test_cloudflare_denied_country() -> None:
    manager = manager_with({"allowed_countries": ["GR"]})

    allowed, country, reason = manager.country_allowed(
        request(
            **{
                "CF-IPCountry": "US",
                "CF-Ray": "abc-IAD",
                "CF-Connecting-IP": "198.51.100.10",
            }
        )
    )

    assert not allowed
    assert country == "US"
    assert reason == "country_not_allowed"


def test_missing_cloudflare_headers_fail_closed_for_public_ip() -> None:
    manager = manager_with(
        {"allowed_countries": ["GR"], "allow_private_networks": True}
    )

    allowed, country, reason = manager.country_allowed(request())
    assert not allowed
    assert country == "UNKNOWN"
    assert reason == "cloudflare_headers_missing"


def test_private_network_can_bypass_geoip_when_enabled() -> None:
    manager = manager_with(
        {"allowed_countries": ["GR"], "allow_private_networks": True}
    )

    allowed, country, reason = manager.country_allowed(request(remote="192.168.1.50"))
    assert allowed
    assert country == "LOCAL"
    assert reason == "private_network"


def test_cloudflare_headers_override_private_proxy_remote_ip() -> None:
    """A private cloudflared proxy address must not bypass country policy."""
    manager = manager_with(
        {"allowed_countries": ["GR"], "allow_private_networks": True}
    )

    allowed, country, reason = manager.country_allowed(
        request(
            remote="172.30.33.5",
            **{
                "CF-IPCountry": "US",
                "CF-Ray": "abc-IAD",
                "CF-Connecting-IP": "198.51.100.10",
            },
        )
    )

    assert not allowed
    assert country == "US"
    assert reason == "country_not_allowed"
