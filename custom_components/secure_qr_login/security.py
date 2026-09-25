"""Security helpers used by Secure QR Login.

Nothing in this module is Home Assistant-specific. Keeping security primitives
small and isolated makes them easier to audit and test.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import secrets
from urllib.parse import urlparse

from aiohttp import web

from .const import DEVICE_SECRET_BYTES, QR_TOKEN_BYTES, SESSION_ID_BYTES


def random_session_id() -> str:
    """Return a high-entropy public session identifier."""
    return secrets.token_urlsafe(SESSION_ID_BYTES)


def random_device_secret() -> str:
    """Return the secret known only to the browser that requested login."""
    return secrets.token_urlsafe(DEVICE_SECRET_BYTES)


def random_qr_token() -> str:
    """Return a short-lived bearer token intended only for the rotating QR."""
    return secrets.token_urlsafe(QR_TOKEN_BYTES)


def secret_digest(value: str) -> str:
    """Return a stable SHA-256 digest for an in-memory secret.

    The plaintext device secret and QR token are never stored in session state.
    """
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def digest_matches(value: str, expected_digest: str) -> bool:
    """Compare a supplied secret to a stored digest in constant time."""
    return hmac.compare_digest(secret_digest(value), expected_digest)


def valid_remote_ip(value: str | None) -> str | None:
    """Return a syntactically valid IP or None."""
    if not value:
        return None
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return None
    return value


def same_origin_request(request: web.Request) -> bool:
    """Require an explicit same-origin browser Origin header.

    All state-changing endpoints are browser POSTs. Modern browsers and the
    Home Assistant Companion WebView send Origin for these fetch requests.
    Missing Origin is rejected instead of being treated as implicitly trusted.
    """
    origin = request.headers.get("Origin")
    if not origin:
        return False

    try:
        parsed = urlparse(origin)
    except ValueError:
        return False

    return (
        parsed.scheme in {"http", "https"}
        and bool(parsed.netloc)
        and parsed.netloc.casefold() == request.host.casefold()
    )


def request_origin(request: web.Request) -> str:
    """Return a verified same-host origin for the HA refresh-token client_id."""
    origin = request.headers.get("Origin") or ""
    try:
        parsed = urlparse(origin)
    except ValueError:
        return ""

    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.netloc
        or parsed.netloc.casefold() != request.host.casefold()
    ):
        return ""

    return f"{parsed.scheme}://{parsed.netloc}/"
