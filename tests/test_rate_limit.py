"""Tests for fixed-window rate limiting."""

from custom_components.secure_qr_login import rate_limit


def test_limiter_enforces_limit_and_resets(monkeypatch) -> None:
    now = 1000.0
    monkeypatch.setattr(rate_limit.time, "time", lambda: now)

    limiter = rate_limit.FixedWindowLimiter(limit=2, window=60)
    assert limiter.allow("client")
    assert limiter.allow("client")
    assert not limiter.allow("client")

    now = 1061.0
    assert limiter.allow("client")


def test_limiter_keeps_keys_independent(monkeypatch) -> None:
    monkeypatch.setattr(rate_limit.time, "time", lambda: 1000.0)

    limiter = rate_limit.FixedWindowLimiter(limit=1, window=60)
    assert limiter.allow("a")
    assert limiter.allow("b")
    assert not limiter.allow("a")
    assert not limiter.allow("b")
