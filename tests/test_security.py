"""Tests for isolated security primitives."""

from types import SimpleNamespace

from custom_components.secure_qr_login.security import (
    digest_matches,
    random_device_secret,
    random_qr_token,
    random_session_id,
    request_origin,
    same_origin_request,
    secret_digest,
    valid_remote_ip,
)


def _request(origin: str | None, host: str = "ha.example.com"):
    headers = {} if origin is None else {"Origin": origin}
    return SimpleNamespace(headers=headers, host=host)


def test_random_values_are_unique_and_separate() -> None:
    sessions = {random_session_id() for _ in range(100)}
    device_secrets = {random_device_secret() for _ in range(100)}
    qr_tokens = {random_qr_token() for _ in range(100)}

    assert len(sessions) == 100
    assert len(device_secrets) == 100
    assert len(qr_tokens) == 100
    assert sessions.isdisjoint(device_secrets)
    assert sessions.isdisjoint(qr_tokens)
    assert device_secrets.isdisjoint(qr_tokens)


def test_digest_matches_only_original_secret() -> None:
    secret = random_device_secret()
    digest = secret_digest(secret)

    assert digest_matches(secret, digest)
    assert not digest_matches(secret + "x", digest)
    assert secret not in digest


def test_valid_remote_ip() -> None:
    assert valid_remote_ip("192.168.1.10") == "192.168.1.10"
    assert valid_remote_ip("2001:db8::1") == "2001:db8::1"
    assert valid_remote_ip("not-an-ip") is None
    assert valid_remote_ip(None) is None


def test_same_origin_accepts_exact_host() -> None:
    assert same_origin_request(_request("https://ha.example.com"))
    assert request_origin(_request("https://ha.example.com")) == "https://ha.example.com/"


def test_same_origin_rejects_different_host_and_lookalike() -> None:
    assert not same_origin_request(_request("https://evil.example.com"))
    assert not same_origin_request(_request("https://ha.example.com.evil.test"))
    assert request_origin(_request("https://evil.example.com")) == ""


def test_originless_request_is_allowed_but_not_trusted_as_client_id() -> None:
    request = _request(None)
    assert same_origin_request(request)
    assert request_origin(request) == ""
