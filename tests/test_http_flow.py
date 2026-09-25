"""End-to-end HTTP security-flow tests.

These tests use Home Assistant's real HTTP test client and registered views.
Only the final HA token-issuance primitive is stubbed so the tests stay focused
on this integration's protocol and security boundaries.
"""

from __future__ import annotations

from types import SimpleNamespace
import time

import pytest

from homeassistant.setup import async_setup_component

from custom_components.secure_qr_login.const import DOMAIN
from custom_components.secure_qr_login.manager import SecureQrLoginManager
from custom_components.secure_qr_login import views


@pytest.fixture
async def qr_manager(hass):
    """Register the real views with an in-memory manager for one test."""
    assert await async_setup_component(hass, "http", {})

    entry = SimpleNamespace(options={})
    manager = SecureQrLoginManager(hass, entry)
    await manager.store.async_load(manager.history_limit)
    hass.data[DOMAIN] = manager
    views.register_views(hass)

    yield manager

    await manager.async_shutdown()
    hass.data.pop(DOMAIN, None)


def _origin(client) -> str:
    return str(client.make_url("/").origin())


async def _start(client, manager):
    manager.enabled_until = time.time() + 180
    response = await client.post(
        "/api/secure_qr_login/start",
        json={},
        headers={"Origin": _origin(client)},
    )
    assert response.status == 200
    return await response.json()


async def _approved_login(client, manager, monkeypatch):
    """Complete start -> QR -> approve -> status and return credentials."""
    monkeypatch.setattr(views, "random_qr_token", lambda: "known-qr-token")
    started = await _start(client, manager)

    response = await client.post(
        "/api/secure_qr_login/qr",
        json={
            "session_id": started["session_id"],
            "device_secret": started["device_secret"],
        },
        headers={"Origin": _origin(client)},
    )
    assert response.status == 200
    assert response.headers["Content-Type"].startswith("image/svg+xml")

    response = await client.get(
        "/api/secure_qr_login/approval",
        params={
            "session_id": started["session_id"],
            "qr_token": "known-qr-token",
        },
    )
    assert response.status == 200

    refresh = SimpleNamespace(id="refresh-id", token="refresh-secret")

    async def fake_issue_tokens(*_args, **_kwargs):
        return refresh, "access-secret", 1800

    monkeypatch.setattr(views, "async_issue_tokens", fake_issue_tokens)

    response = await client.post(
        "/api/secure_qr_login/approval/action",
        json={
            "session_id": started["session_id"],
            "qr_token": "known-qr-token",
            "action": "approve",
        },
        headers={"Origin": _origin(client)},
    )
    assert response.status == 200

    response = await client.post(
        "/api/secure_qr_login/status",
        json={
            "session_id": started["session_id"],
            "device_secret": started["device_secret"],
        },
        headers={"Origin": _origin(client)},
    )
    assert response.status == 200
    credentials = await response.json()
    return started, credentials


async def test_full_login_flow_is_single_use(
    hass_client,
    qr_manager,
    monkeypatch,
) -> None:
    """Credentials are returned exactly once to the device-secret holder."""
    client = await hass_client()
    started, credentials = await _approved_login(client, qr_manager, monkeypatch)

    assert credentials["status"] == "approved"
    assert credentials["access_token"] == "access-secret"
    assert credentials["refresh_token"] == "refresh-secret"

    response = await client.post(
        "/api/secure_qr_login/status",
        json={
            "session_id": started["session_id"],
            "device_secret": started["device_secret"],
        },
        headers={"Origin": _origin(client)},
    )
    assert response.status == 404

    active = qr_manager.active_logins[started["session_id"]]
    assert active.delivered is True


async def test_post_without_origin_is_rejected(
    hass_client,
    qr_manager,
) -> None:
    """State-changing browser requests require an explicit same-origin Origin."""
    qr_manager.enabled_until = time.time() + 180
    client = await hass_client()

    response = await client.post("/api/secure_qr_login/start", json={})
    assert response.status == 403
    assert (await response.json())["error"] == "origin_rejected"


async def test_old_qr_token_cannot_be_replayed(
    hass_client,
    qr_manager,
    monkeypatch,
) -> None:
    """Only the latest rotating QR token is valid."""
    tokens = iter(("qr-one", "qr-two"))
    monkeypatch.setattr(views, "random_qr_token", lambda: next(tokens))

    client = await hass_client()
    started = await _start(client, qr_manager)
    payload = {
        "session_id": started["session_id"],
        "device_secret": started["device_secret"],
    }
    headers = {"Origin": _origin(client)}

    assert (
        await client.post(
            "/api/secure_qr_login/qr",
            json=payload,
            headers=headers,
        )
    ).status == 200
    assert (
        await client.post(
            "/api/secure_qr_login/qr",
            json=payload,
            headers=headers,
        )
    ).status == 200

    old = await client.get(
        "/api/secure_qr_login/approval",
        params={"session_id": started["session_id"], "qr_token": "qr-one"},
    )
    assert old.status == 410

    current = await client.get(
        "/api/secure_qr_login/approval",
        params={"session_id": started["session_id"], "qr_token": "qr-two"},
    )
    assert current.status == 200


async def test_repeated_wrong_device_secret_destroys_session(
    hass_client,
    qr_manager,
) -> None:
    """Five invalid device-secret attempts permanently lock that request."""
    client = await hass_client()
    started = await _start(client, qr_manager)
    headers = {"Origin": _origin(client)}

    for _ in range(4):
        response = await client.post(
            "/api/secure_qr_login/status",
            json={
                "session_id": started["session_id"],
                "device_secret": "wrong-secret",
            },
            headers=headers,
        )
        assert response.status == 403

    fifth = await client.post(
        "/api/secure_qr_login/status",
        json={
            "session_id": started["session_id"],
            "device_secret": "wrong-secret",
        },
        headers=headers,
    )
    assert fifth.status == 410
    assert (await fifth.json())["error"] == "session_locked"
    assert started["session_id"] not in qr_manager.sessions


async def test_clear_history_keeps_active_login_and_revoke_all_removes_it(
    hass_client,
    qr_manager,
    monkeypatch,
) -> None:
    """Admin maintenance operations keep history and token actions separated."""
    client = await hass_client()
    started, _credentials = await _approved_login(client, qr_manager, monkeypatch)
    headers = {"Origin": _origin(client)}

    assert started["session_id"] in qr_manager.active_logins
    assert qr_manager.history

    response = await client.post(
        "/api/secure_qr_login/admin/clear-history",
        json={},
        headers=headers,
    )
    assert response.status == 200
    assert qr_manager.history == []
    assert started["session_id"] in qr_manager.active_logins

    qr_manager.enabled_until = time.time() + 180
    response = await client.post(
        "/api/secure_qr_login/admin/revoke-all",
        json={},
        headers=headers,
    )
    assert response.status == 200
    payload = await response.json()
    assert payload["count"] == 1
    assert not qr_manager.enabled
    assert qr_manager.active_logins == {}


async def test_country_allowlist_allows_matching_local_geoip(
    hass_client,
    qr_manager,
    monkeypatch,
) -> None:
    """A matching local GeoIP country may start a QR login."""
    from custom_components.secure_qr_login.geoip import GeoIPResult

    qr_manager.entry.options = {
        "allowed_countries": ["GR"],
        "allow_private_networks": False,
    }

    async def fake_lookup(_ip):
        return GeoIPResult("GR", "local_database", "8.8.8.8", "resolved")

    monkeypatch.setattr(qr_manager.geoip, "async_lookup_ip", fake_lookup)
    qr_manager.enabled_until = time.time() + 180
    client = await hass_client()

    response = await client.post(
        "/api/secure_qr_login/start",
        json={},
        headers={"Origin": _origin(client)},
    )

    assert response.status == 200


async def test_country_allowlist_denies_non_matching_local_geoip(
    hass_client,
    qr_manager,
    monkeypatch,
) -> None:
    """A non-matching local GeoIP country is rejected before session creation."""
    from custom_components.secure_qr_login.geoip import GeoIPResult

    qr_manager.entry.options = {
        "allowed_countries": ["GR"],
        "allow_private_networks": False,
    }

    async def fake_lookup(_ip):
        return GeoIPResult("US", "local_database", "8.8.8.8", "resolved")

    monkeypatch.setattr(qr_manager.geoip, "async_lookup_ip", fake_lookup)
    qr_manager.enabled_until = time.time() + 180
    client = await hass_client()

    response = await client.post(
        "/api/secure_qr_login/start",
        json={},
        headers={"Origin": _origin(client)},
    )

    assert response.status == 403
    payload = await response.json()
    assert payload["error"] == "country_not_allowed"
    assert payload["country"] == "US"
    assert not qr_manager.sessions


async def test_spoofed_cloudflare_country_header_does_not_override_local_geoip(
    hass_client,
    qr_manager,
    monkeypatch,
) -> None:
    """Caller-provided country headers are not trusted as policy input."""
    from custom_components.secure_qr_login.geoip import GeoIPResult

    qr_manager.entry.options = {"allowed_countries": ["GR"]}

    async def fake_lookup(_ip):
        return GeoIPResult("US", "local_database", "8.8.8.8", "resolved")

    monkeypatch.setattr(qr_manager.geoip, "async_lookup_ip", fake_lookup)
    qr_manager.enabled_until = time.time() + 180
    client = await hass_client()

    response = await client.post(
        "/api/secure_qr_login/start",
        json={},
        headers={
            "Origin": _origin(client),
            "CF-IPCountry": "GR",
            "CF-Ray": "fake",
            "CF-Connecting-IP": "1.1.1.1",
        },
    )

    assert response.status == 403
    assert (await response.json())["country"] == "US"


async def test_admin_settings_api_saves_validated_values(
    hass_client,
    qr_manager,
    monkeypatch,
) -> None:
    """Admin settings are validated server-side before they are persisted."""
    client = await hass_client()
    captured = {}

    async def fake_update_settings(options):
        captured.update(options)

    monkeypatch.setattr(qr_manager, "async_update_settings", fake_update_settings)

    response = await client.post(
        "/api/secure_qr_login/admin/settings",
        json={
            "enable_window_seconds": 180,
            "qr_lifetime_seconds": 10,
            "max_pending_sessions": 3,
            "history_limit": 100,
            "allowed_user_ids": [],
            "notify_services": [],
            "notify_on_approved": True,
            "notify_on_denied": True,
            "allowed_countries": ["gr", "DE", "GR"],
            "allow_private_networks": True,
        },
        headers={"Origin": _origin(client)},
    )

    assert response.status == 200
    assert captured["allowed_countries"] == ["GR", "DE"]
    assert captured["allow_private_networks"] is True


async def test_admin_settings_api_rejects_invalid_country_code(
    hass_client,
    qr_manager,
) -> None:
    """Arbitrary two-letter strings are not accepted as countries."""
    client = await hass_client()

    response = await client.post(
        "/api/secure_qr_login/admin/settings",
        json={
            "enable_window_seconds": 180,
            "qr_lifetime_seconds": 10,
            "max_pending_sessions": 3,
            "history_limit": 100,
            "allowed_user_ids": [],
            "notify_services": [],
            "notify_on_approved": True,
            "notify_on_denied": True,
            "allowed_countries": ["ZZ"],
            "allow_private_networks": True,
        },
        headers={"Origin": _origin(client)},
    )

    assert response.status == 400
    assert (await response.json())["error"] == "invalid_country_code"


async def test_admin_can_trigger_manual_geoip_update(
    hass_client,
    qr_manager,
    monkeypatch,
) -> None:
    """Manual GeoIP maintenance is admin-only and returns update health."""
    from custom_components.secure_qr_login.geoip import GeoIPUpdateResult

    client = await hass_client()

    async def fake_manual_update():
        return GeoIPUpdateResult(
            success=True,
            updated=False,
            status="up_to_date",
            release="2026-09",
            error=None,
            attempted_at="2026-09-25T18:00:00+00:00",
            successful_at="2026-09-01T00:00:00+00:00",
        )

    monkeypatch.setattr(qr_manager, "async_manual_geoip_update", fake_manual_update)

    response = await client.post(
        "/api/secure_qr_login/admin/geoip-update",
        json={},
        headers={"Origin": _origin(client)},
    )

    assert response.status == 200
    payload = await response.json()
    assert payload["status"] == "up_to_date"
    assert payload["release"] == "2026-09"
