"""Tests for bounded configuration and user allowlist policy."""

from types import SimpleNamespace

from custom_components.secure_qr_login.manager import SecureQrLoginManager


def manager_with(options: dict) -> SecureQrLoginManager:
    manager = object.__new__(SecureQrLoginManager)
    manager.entry = SimpleNamespace(options=options)
    return manager


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
