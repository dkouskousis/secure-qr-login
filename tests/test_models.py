"""Tests for session and persistent metadata models."""

import time

from custom_components.secure_qr_login.models import ActiveLogin, AuditEntry, LoginSession
from custom_components.secure_qr_login.security import secret_digest


def make_session() -> tuple[LoginSession, str, str]:
    device_secret = "device-secret"
    qr_token = "qr-token"
    now = time.time()
    session = LoginSession(
        session_id="session",
        device_secret_digest=secret_digest(device_secret),
        client_ip="192.0.2.10",
        user_agent="Test Browser",
        client_id="https://ha.example.com/",
        created_at=now,
        expires_at=now + 60,
        qr_token_digest=secret_digest(qr_token),
        qr_expires_at=now + 10,
    )
    return session, device_secret, qr_token


def test_device_secret_and_qr_token_are_independent() -> None:
    session, device_secret, qr_token = make_session()

    assert session.device_secret_valid(device_secret)
    assert not session.device_secret_valid(qr_token)
    assert session.qr_valid(qr_token)
    assert not session.qr_valid(device_secret)


def test_expired_qr_cannot_be_replayed() -> None:
    session, _, qr_token = make_session()
    session.qr_expires_at = time.time() - 1

    assert not session.qr_valid(qr_token)


def test_expired_session() -> None:
    session, _, _ = make_session()
    session.expires_at = time.time() - 1

    assert session.expired()


def test_public_status_never_contains_credentials() -> None:
    session, _, _ = make_session()
    session.access_token = "access-secret"
    session.refresh_token = object()

    payload = session.public_status()
    rendered = repr(payload)

    assert "access-secret" not in rendered
    assert "refresh" not in rendered.lower()


def test_active_login_storage_contains_only_internal_token_id() -> None:
    record = ActiveLogin(
        login_id="login-id",
        refresh_token_id="internal-token-id",
        user_id="user-id",
        user_name="User",
        client_ip="192.0.2.1",
        user_agent="Browser",
        approved_at=123.0,
        delivered=True,
        delivered_at=124.0,
    )

    stored = record.as_storage()
    assert stored["refresh_token_id"] == "internal-token-id"
    assert "access_token" not in stored
    assert "refresh_token" not in stored


def test_audit_round_trip() -> None:
    entry = AuditEntry(
        event="approved",
        session_id="session",
        client_ip="192.0.2.5",
        user_id="user",
        user_name="User",
        detail="detail",
    )
    restored = AuditEntry.from_dict(entry.as_dict())

    assert restored.event == entry.event
    assert restored.session_id == entry.session_id
    assert restored.detail == entry.detail
