"""HTTP views for Secure QR Login.

Security model
--------------
* QR login is disabled by default and opens for at most three minutes.
* A public session id identifies a request but is never sufficient to fetch tokens.
* The requesting browser receives a separate high-entropy device secret.
* Only a SHA-256 digest of that device secret is stored in session state.
* Every displayed QR carries an independent token valid for ten seconds.
* Approval requires a normal authenticated Home Assistant user plus the current QR token.
* Token retrieval requires the device secret and is single-use.
"""

from __future__ import annotations

from io import BytesIO
import logging
from pathlib import Path
import time

from aiohttp import web
import segno

from homeassistant.components.http import HomeAssistantView
from homeassistant.core import HomeAssistant

from .auth import async_issue_tokens
from .const import (
    DOMAIN,
    GLOBAL_START_LIMIT,
    GLOBAL_START_WINDOW_SECONDS,
    QR_LIFETIME_SECONDS,
    START_LIMIT_PER_IP,
    START_LIMIT_WINDOW_SECONDS,
    STATUS_LIMIT_PER_IP,
    STATUS_LIMIT_WINDOW_SECONDS,
)
from .models import AuditEntry, LoginSession
from .rate_limit import FixedWindowLimiter
from .security import (
    random_device_secret,
    random_qr_token,
    random_session_id,
    request_origin,
    same_origin_request,
    secret_digest,
)

_LOGGER = logging.getLogger(__name__)
WWW_DIR = Path(__file__).parent / "www"

_START_IP_LIMITER = FixedWindowLimiter(START_LIMIT_PER_IP, START_LIMIT_WINDOW_SECONDS)
_START_GLOBAL_LIMITER = FixedWindowLimiter(GLOBAL_START_LIMIT, GLOBAL_START_WINDOW_SECONDS)
_STATUS_IP_LIMITER = FixedWindowLimiter(STATUS_LIMIT_PER_IP, STATUS_LIMIT_WINDOW_SECONDS)

NO_STORE_HEADERS = {
    "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
    "Pragma": "no-cache",
    "X-Content-Type-Options": "nosniff",
}
PAGE_HEADERS = {
    **NO_STORE_HEADERS,
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "SAMEORIGIN",
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' blob: data:; connect-src 'self'; frame-ancestors 'self'; "
        "base-uri 'none'; form-action 'self'"
    ),
}


def _manager(request: web.Request):
    return request.app["hass"].data.get(DOMAIN)


async def _json_body(request: web.Request) -> dict | None:
    try:
        value = await request.json()
    except Exception:
        return None
    return value if isinstance(value, dict) else None


def _clean(value, limit: int = 255) -> str:
    return value.strip()[:limit] if isinstance(value, str) else ""


def _json(view: HomeAssistantView, payload: dict, status: int = 200):
    return view.json(payload, status_code=status, headers=NO_STORE_HEADERS)


def _reject_cross_origin(view: HomeAssistantView, request: web.Request):
    if same_origin_request(request):
        return None
    return _json(view, {"error": "origin_rejected"}, 403)


def _client_ip(request: web.Request) -> str:
    return request.remote or "unknown"


def _get_session(manager, session_id: str) -> LoginSession | None:
    session = manager.sessions.get(session_id)
    if session is None:
        return None
    if session.expired():
        manager.sessions.pop(session_id, None)
        return None
    return session


class StartView(HomeAssistantView):
    url = "/api/secure_qr_login/start"
    name = "api:secure_qr_login:start"
    requires_auth = False

    async def post(self, request: web.Request) -> web.Response:
        if rejected := _reject_cross_origin(self, request):
            return rejected
        manager = _manager(request)
        if manager is None or not manager.enabled:
            return _json(self, {"error": "disabled"}, 503)

        ip = _client_ip(request)
        if not _START_IP_LIMITER.allow(ip) or not _START_GLOBAL_LIMITER.allow("global"):
            return _json(self, {"error": "rate_limited"}, 429)

        session_id = random_session_id()
        device_secret = random_device_secret()
        now = time.time()
        session = LoginSession(
            session_id=session_id,
            device_secret_digest=secret_digest(device_secret),
            client_ip=ip,
            user_agent=_clean(request.headers.get("User-Agent")) or "unknown",
            client_id=request_origin(request),
            created_at=now,
            expires_at=manager.new_session_expiry(),
        )
        manager.sessions[session_id] = session
        manager.audit.appendleft(
            AuditEntry(event="session_started", session_id=session_id, client_ip=ip)
        )
        return _json(
            self,
            {
                "session_id": session_id,
                "device_secret": device_secret,
                "expires_in": max(0, int(session.expires_at - now)),
                "qr_lifetime": QR_LIFETIME_SECONDS,
            },
        )


class QrView(HomeAssistantView):
    """Rotate the QR token and return the QR itself as SVG."""

    url = "/api/secure_qr_login/qr"
    name = "api:secure_qr_login:qr"
    requires_auth = False

    async def post(self, request: web.Request) -> web.Response:
        if rejected := _reject_cross_origin(self, request):
            return rejected
        manager = _manager(request)
        if manager is None or not manager.enabled:
            return _json(self, {"error": "disabled"}, 503)

        payload = await _json_body(request)
        if payload is None:
            return _json(self, {"error": "invalid_json"}, 400)
        session_id = _clean(payload.get("session_id"), 128)
        device_secret = _clean(payload.get("device_secret"), 256)
        session = _get_session(manager, session_id)
        if session is None:
            return _json(self, {"error": "session_not_found"}, 404)
        if session.status != "pending":
            return _json(self, {"error": "session_not_pending"}, 409)
        if not session.device_secret_valid(device_secret):
            return _json(self, {"error": "invalid_session_secret"}, 403)

        qr_token = random_qr_token()
        session.qr_token_digest = secret_digest(qr_token)
        session.qr_expires_at = min(
            time.time() + QR_LIFETIME_SECONDS,
            session.expires_at,
            manager.enabled_until,
        )
        base_url = session.client_id.rstrip("/") if session.client_id else f"{request.scheme}://{request.host}"
        approval_url = (
            f"{base_url}/secure_qr_login/approve"
            f"?session_id={session.session_id}&qr_token={qr_token}"
        )
        qr = segno.make(approval_url, error="m")
        output = BytesIO()
        qr.save(output, kind="svg", scale=5, border=4, xmldecl=False, nl=False)
        return web.Response(
            body=output.getvalue(),
            content_type="image/svg+xml",
            headers={
                **NO_STORE_HEADERS,
                "X-QR-Expires-In": str(QR_LIFETIME_SECONDS),
            },
        )


class StatusView(HomeAssistantView):
    """Return status, and once approved deliver credentials exactly once."""

    url = "/api/secure_qr_login/status"
    name = "api:secure_qr_login:status"
    requires_auth = False

    async def post(self, request: web.Request) -> web.Response:
        if rejected := _reject_cross_origin(self, request):
            return rejected
        ip = _client_ip(request)
        if not _STATUS_IP_LIMITER.allow(ip):
            return _json(self, {"error": "rate_limited"}, 429)
        manager = _manager(request)
        if manager is None or not manager.enabled:
            return _json(self, {"error": "disabled"}, 503)

        payload = await _json_body(request)
        if payload is None:
            return _json(self, {"error": "invalid_json"}, 400)
        session_id = _clean(payload.get("session_id"), 128)
        device_secret = _clean(payload.get("device_secret"), 256)
        session = _get_session(manager, session_id)
        if session is None:
            return _json(self, {"error": "session_not_found"}, 404)
        if not session.device_secret_valid(device_secret):
            return _json(self, {"error": "invalid_session_secret"}, 403)

        if session.status == "approved":
            if session.consumed or session.refresh_token is None or not session.access_token:
                manager.sessions.pop(session_id, None)
                return _json(self, {"error": "already_consumed"}, 410)

            session.consumed = True
            response = {
                "status": "approved",
                "access_token": session.access_token,
                "refresh_token": session.refresh_token.token,
                "token_expires_in": session.token_expires_in,
            }
            manager.audit.appendleft(
                AuditEntry(
                    event="credentials_consumed",
                    session_id=session.session_id,
                    client_ip=session.client_ip,
                    user_id=session.approved_user_id,
                    user_name=session.approved_user_name,
                )
            )
            manager.sessions.pop(session_id, None)
            session.access_token = None
            session.refresh_token = None
            return _json(self, response)

        return _json(self, session.public_status())


class ApprovalDetailsView(HomeAssistantView):
    url = "/api/secure_qr_login/approval"
    name = "api:secure_qr_login:approval"
    requires_auth = True

    async def get(self, request: web.Request) -> web.Response:
        manager = _manager(request)
        if manager is None or not manager.enabled:
            return _json(self, {"error": "disabled"}, 503)
        session_id = _clean(request.query.get("session_id"), 128)
        qr_token = _clean(request.query.get("qr_token"), 256)
        session = _get_session(manager, session_id)
        if session is None:
            return _json(self, {"error": "session_not_found"}, 404)
        if session.status != "pending":
            return _json(self, {"error": "session_not_pending"}, 409)
        if not session.qr_valid(qr_token):
            return _json(self, {"error": "qr_expired"}, 410)

        approver = request["hass_user"]
        details = session.approval_details()
        details["account"] = approver.name or approver.id
        return _json(self, details)


class ApprovalActionView(HomeAssistantView):
    url = "/api/secure_qr_login/approval/action"
    name = "api:secure_qr_login:approval_action"
    requires_auth = True

    async def post(self, request: web.Request) -> web.Response:
        if rejected := _reject_cross_origin(self, request):
            return rejected
        manager = _manager(request)
        if manager is None or not manager.enabled:
            return _json(self, {"error": "disabled"}, 503)
        payload = await _json_body(request)
        if payload is None:
            return _json(self, {"error": "invalid_json"}, 400)

        session_id = _clean(payload.get("session_id"), 128)
        qr_token = _clean(payload.get("qr_token"), 256)
        action = _clean(payload.get("action"), 16)
        if action not in {"approve", "deny"}:
            return _json(self, {"error": "invalid_action"}, 400)

        session = _get_session(manager, session_id)
        if session is None:
            return _json(self, {"error": "session_not_found"}, 404)
        if session.status != "pending":
            return _json(self, {"error": "session_not_pending"}, 409)
        if not session.qr_valid(qr_token):
            return _json(self, {"error": "qr_expired"}, 410)

        approver = request["hass_user"]
        approver_name = approver.name or approver.id
        if action == "deny":
            session.status = "denied"
            manager.audit.appendleft(
                AuditEntry(
                    event="denied",
                    session_id=session.session_id,
                    client_ip=session.client_ip,
                    user_id=approver.id,
                    user_name=approver_name,
                )
            )
            return _json(self, {"status": "denied"})

        try:
            refresh_token, access_token, expires_in = await async_issue_tokens(
                request.app["hass"],
                approver,
                client_id=session.client_id,
                remote_ip=session.client_ip,
            )
        except Exception:
            _LOGGER.exception("Failed issuing token for Secure QR Login session")
            return _json(self, {"error": "token_creation_failed"}, 500)

        session.refresh_token = refresh_token
        session.access_token = access_token
        session.token_expires_in = expires_in
        session.approved_user_id = approver.id
        session.approved_user_name = approver_name
        session.approved_at = time.time()
        session.status = "approved"
        session.qr_token_digest = ""
        session.qr_expires_at = 0.0
        manager.audit.appendleft(
            AuditEntry(
                event="approved",
                session_id=session.session_id,
                client_ip=session.client_ip,
                user_id=approver.id,
                user_name=approver_name,
            )
        )
        return _json(self, {"status": "approved", "account": approver_name})


class AdminStateView(HomeAssistantView):
    url = "/api/secure_qr_login/admin/state"
    name = "api:secure_qr_login:admin_state"
    requires_auth = True

    async def get(self, request: web.Request) -> web.Response:
        user = request["hass_user"]
        if not user.is_admin:
            return _json(self, {"error": "admin_required"}, 403)
        manager = _manager(request)
        if manager is None:
            return _json(self, {"error": "not_ready"}, 503)
        return _json(
            self,
            {
                "enabled": manager.enabled,
                "remaining_seconds": manager.enabled_remaining,
                "pending_sessions": sum(
                    1 for session in manager.sessions.values()
                    if session.status == "pending" and not session.expired()
                ),
                "audit": [entry.as_dict() for entry in list(manager.audit)[:20]],
            },
        )


class AdminWindowView(HomeAssistantView):
    url = "/api/secure_qr_login/admin/window"
    name = "api:secure_qr_login:admin_window"
    requires_auth = True

    async def post(self, request: web.Request) -> web.Response:
        if rejected := _reject_cross_origin(self, request):
            return rejected
        user = request["hass_user"]
        if not user.is_admin:
            return _json(self, {"error": "admin_required"}, 403)
        manager = _manager(request)
        if manager is None:
            return _json(self, {"error": "not_ready"}, 503)
        payload = await _json_body(request)
        if payload is None or payload.get("enabled") not in {True, False}:
            return _json(self, {"error": "invalid_request"}, 400)
        if payload["enabled"]:
            await manager.async_enable()
        else:
            await manager.async_disable("admin_disabled")
        return _json(
            self,
            {"enabled": manager.enabled, "remaining_seconds": manager.enabled_remaining},
        )


class _PageView(HomeAssistantView):
    requires_auth = False
    filename = ""

    async def get(self, request: web.Request) -> web.Response:
        path = WWW_DIR / self.filename
        if not path.is_file():
            return web.Response(text="Not found", status=404)
        return web.FileResponse(path, headers=PAGE_HEADERS)


class StartPageView(_PageView):
    url = "/secure_qr_login/start"
    name = "secure_qr_login:start_page"
    filename = "start.html"


class ApprovePageView(_PageView):
    url = "/secure_qr_login/approve"
    name = "secure_qr_login:approve_page"
    filename = "approve.html"


class AdminPageView(_PageView):
    url = "/secure_qr_login/admin"
    name = "secure_qr_login:admin_page"
    filename = "admin.html"


class StaticView(HomeAssistantView):
    url = "/secure_qr_login/static/{filename}"
    name = "secure_qr_login:static"
    requires_auth = False

    _ALLOWED = {
        "start.js": "application/javascript",
        "approve.js": "application/javascript",
        "admin.js": "application/javascript",
    }

    async def get(self, request: web.Request, filename: str) -> web.Response:
        content_type = self._ALLOWED.get(filename)
        if content_type is None:
            return web.Response(text="Not found", status=404)
        path = WWW_DIR / "static" / filename
        if not path.is_file():
            return web.Response(text="Not found", status=404)
        return web.FileResponse(
            path,
            headers={
                "Content-Type": content_type,
                "Cache-Control": "no-cache",
                "X-Content-Type-Options": "nosniff",
            },
        )


def register_views(hass: HomeAssistant) -> None:
    """Register all HTTP views once."""
    for view in (
        StartView(),
        QrView(),
        StatusView(),
        ApprovalDetailsView(),
        ApprovalActionView(),
        AdminStateView(),
        AdminWindowView(),
        StartPageView(),
        ApprovePageView(),
        AdminPageView(),
        StaticView(),
    ):
        hass.http.register_view(view)
