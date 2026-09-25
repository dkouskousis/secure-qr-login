"""End-to-end HTTP security-flow tests.

These tests use Home Assistant's real HTTP test client and registered views.
Only the final HA token-issuance primitive is stubbed so the tests stay focused
on this integration's protocol and security boundaries.
"""

from __future__ import annotations

from types import SimpleNamespace
import time

import pytest

from custom_components.secure_qr_login.const import DOMAIN
from custom_components.secure_qr_login.manager import SecureQrLoginManager
from custom_components.secure_qr_login import views


@pytest.fixture
async def qr_manager(hass):
    """Register the real views with an in-memory manager for one test."""
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

    # The session is removed immediately after one-time delivery.
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

    assert (await client.post("/api/secure_qr_login/qr", json=payload, headers=headers)).status == 200
    assert (await client.post("/api/secure_qr_login/qr", json=payload, headers=headers)).status == 200

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

    # Re-open the window to verify revoke-all closes it as part of fail-safe
    # bulk revocation.
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
