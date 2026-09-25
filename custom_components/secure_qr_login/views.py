"""HTTP views for Secure QR Login.

Security model
--------------
* QR login is disabled by default and opens only for a bounded admin window.
* A public session id is never sufficient to retrieve HA credentials.
* The requesting browser holds a separate high-entropy device secret.
* Only SHA-256 digests of device/QR secrets are retained server-side.
* QR bearer tokens rotate frequently and can approve/deny only.
* Credential retrieval is single-use and requires the device secret.
* Repeated invalid device-secret attempts destroy the target session.
* Optional country restriction is an additional Cloudflare-backed policy layer.
* Issued refresh tokens are persisted only by their non-secret internal id so
  administrators can revoke them later and orphaned tokens can be cleaned up.
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

from .auth import async_issue_tokens, async_revoke_refresh_token
from .const import (
    CONF_ALLOWED_COUNTRIES,
    CONF_ALLOWED_USER_IDS,
    CONF_ALLOW_PRIVATE_NETWORKS,
    CONF_ENABLE_WINDOW_SECONDS,
    CONF_HISTORY_LIMIT,
    CONF_MAX_PENDING_SESSIONS,
    CONF_NOTIFY_ON_APPROVED,
    CONF_NOTIFY_ON_DENIED,
    CONF_NOTIFY_SERVICES,
    CONF_QR_LIFETIME_SECONDS,
    DEFAULT_ALLOWED_COUNTRIES,
    DEFAULT_ALLOWED_USER_IDS,
    DEFAULT_ALLOW_PRIVATE_NETWORKS,
    DEFAULT_ENABLE_WINDOW_SECONDS,
    DEFAULT_HISTORY_LIMIT,
    DEFAULT_MAX_PENDING_SESSIONS,
    DEFAULT_NOTIFY_ON_APPROVED,
    DEFAULT_NOTIFY_ON_DENIED,
    DEFAULT_NOTIFY_SERVICES,
    DEFAULT_QR_LIFETIME_SECONDS,
    DOMAIN,
    GLOBAL_START_LIMIT,
    GLOBAL_START_WINDOW_SECONDS,
    ISO_COUNTRY_CODES,
    MAX_ENABLE_WINDOW_SECONDS,
    MAX_HISTORY_LIMIT,
    MAX_MAX_PENDING_SESSIONS,
    MAX_QR_LIFETIME_SECONDS,
    MIN_ENABLE_WINDOW_SECONDS,
    MIN_HISTORY_LIMIT,
    MIN_MAX_PENDING_SESSIONS,
    MIN_QR_LIFETIME_SECONDS,
    START_LIMIT_PER_IP,
    START_LIMIT_WINDOW_SECONDS,
    STATUS_LIMIT_PER_IP,
    STATUS_LIMIT_WINDOW_SECONDS,
    VERSION,
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
        "default-src 'self'; script-src 'self'; style-src 'self'; "
        "img-src 'self' blob: data:; connect-src 'self'; frame-ancestors 'self'; "
        "base-uri 'none'; form-action 'self'; object-src 'none'"
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
    """Reject POSTs without an explicit same-origin Origin header."""
    if same_origin_request(request):
        return None
    return _json(view, {"error": "origin_rejected"}, 403)


def _reject_country(view: HomeAssistantView, request: web.Request, manager):
    """Enforce the optional country allowlist on the requesting browser."""
    allowed, country, reason = manager.country_allowed(request)
    if allowed:
        return None

    return _json(
        view,
        {
            "error": "country_not_allowed",
            "country": country,
            "reason": reason,
        },
        403,
    )


def _client_ip(request: web.Request) -> str:
    return request.remote or "unknown"


def _get_session(manager, session_id: str) -> LoginSession | None:
    session = manager.sessions.get(session_id)
    if session is None or session.expired():
        return None
    return session


def _require_admin(view: HomeAssistantView, request: web.Request):
    user = request["hass_user"]
    if user.is_admin:
        return None
    return _json(view, {"error": "admin_required"}, 403)


async def _validate_device_secret(
    view: HomeAssistantView,
    manager,
    session: LoginSession,
    supplied_secret: str,
):
    valid, locked = await manager.async_validate_device_secret(
        session,
        supplied_secret,
    )
    if valid:
        return None
    if locked:
        return _json(view, {"error": "session_locked"}, 410)
    return _json(view, {"error": "invalid_session_secret"}, 403)


def _validate_int(
    payload: dict,
    key: str,
    minimum: int,
    maximum: int,
) -> int | None:
    value = payload.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    if not minimum <= value <= maximum:
        return None
    return value


def _validate_string_list(value, *, maximum: int = 256) -> list[str] | None:
    if not isinstance(value, list) or len(value) > maximum:
        return None
    if not all(isinstance(item, str) for item in value):
        return None
    return list(dict.fromkeys(value))


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
        if rejected := _reject_country(self, request, manager):
            return rejected

        ip = _client_ip(request)
        if (
            not _START_IP_LIMITER.allow(ip)
            or not _START_GLOBAL_LIMITER.allow("global")
        ):
            return _json(self, {"error": "rate_limited"}, 429)

        if manager.pending_count >= manager.max_pending_sessions:
            return _json(self, {"error": "pending_limit_reached"}, 429)

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
        await manager.async_record(
            AuditEntry(
                event="session_started",
                session_id=session_id,
                client_ip=ip,
            )
        )
        return _json(
            self,
            {
                "session_id": session_id,
                "device_secret": device_secret,
                "expires_in": max(0, int(session.expires_at - now)),
                "qr_lifetime": manager.qr_lifetime_seconds,
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
        if rejected := _reject_country(self, request, manager):
            return rejected

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
        if rejected := await _validate_device_secret(
            self, manager, session, device_secret
        ):
            return rejected

        qr_token = random_qr_token()
        qr_lifetime = manager.qr_lifetime_seconds
        session.qr_token_digest = secret_digest(qr_token)
        session.qr_expires_at = min(
            time.time() + qr_lifetime,
            session.expires_at,
            manager.enabled_until,
        )

        base_url = (
            session.client_id.rstrip("/")
            if session.client_id
            else f"{request.scheme}://{request.host}"
        )
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
                "X-QR-Expires-In": str(qr_lifetime),
            },
        )


class StatusView(HomeAssistantView):
    """Return status and deliver approved credentials exactly once."""

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
        if rejected := _reject_country(self, request, manager):
            return rejected

        payload = await _json_body(request)
        if payload is None:
            return _json(self, {"error": "invalid_json"}, 400)

        session_id = _clean(payload.get("session_id"), 128)
        device_secret = _clean(payload.get("device_secret"), 256)
        session = _get_session(manager, session_id)
        if session is None:
            return _json(self, {"error": "session_not_found"}, 404)
        if rejected := await _validate_device_secret(
            self, manager, session, device_secret
        ):
            return rejected

        if session.status == "denied":
            response = session.public_status()
            manager.sessions.pop(session_id, None)
            return _json(self, response)

        if session.status != "approved":
            return _json(self, session.public_status())

        if (
            session.consumed
            or session.refresh_token is None
            or not session.access_token
        ):
            manager.sessions.pop(session_id, None)
            return _json(self, {"error": "already_consumed"}, 410)

        try:
            await manager.async_mark_consumed(session)
        except Exception:
            _LOGGER.exception("Unable to persist consumed Secure QR Login session")
            await async_revoke_refresh_token(
                request.app["hass"],
                session.refresh_token,
            )
            manager.store.active.pop(session.session_id, None)
            await manager.store.async_save(manager.history_limit)
            manager.sessions.pop(session_id, None)
            return _json(self, {"error": "credential_delivery_failed"}, 500)

        session.consumed = True
        response = {
            "status": "approved",
            "access_token": session.access_token,
            "refresh_token": session.refresh_token.token,
            "token_expires_in": session.token_expires_in,
        }
        manager.sessions.pop(session_id, None)
        session.access_token = None
        session.refresh_token = None
        return _json(self, response)


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
        if not manager.user_allowed(approver):
            return _json(self, {"error": "user_not_allowed"}, 403)

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
        if not manager.user_allowed(approver):
            return _json(self, {"error": "user_not_allowed"}, 403)

        approver_name = approver.name or approver.id

        if action == "deny":
            session.status = "denied"
            session.invalidate_qr()
            await manager.async_record(
                AuditEntry(
                    event="denied",
                    session_id=session.session_id,
                    client_ip=session.client_ip,
                    user_id=approver.id,
                    user_name=approver_name,
                )
            )
            await manager.async_notify_result("denied", session, approver_name)
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
        session.invalidate_qr()

        try:
            await manager.async_track_issued(session)
        except Exception:
            _LOGGER.exception("Unable to persist issued Secure QR Login token")
            await async_revoke_refresh_token(request.app["hass"], refresh_token)
            session.refresh_token = None
            session.access_token = None
            session.status = "error"
            return _json(self, {"error": "token_tracking_failed"}, 500)

        await manager.async_record(
            AuditEntry(
                event="approved",
                session_id=session.session_id,
                client_ip=session.client_ip,
                user_id=approver.id,
                user_name=approver_name,
            )
        )
        await manager.async_notify_result("approved", session, approver_name)
        return _json(self, {"status": "approved", "account": approver_name})


class AdminStateView(HomeAssistantView):
    url = "/api/secure_qr_login/admin/state"
    name = "api:secure_qr_login:admin_state"
    requires_auth = True

    async def get(self, request: web.Request) -> web.Response:
        if rejected := _require_admin(self, request):
            return rejected

        manager = _manager(request)
        if manager is None:
            return _json(self, {"error": "not_ready"}, 503)

        active = await manager.async_get_active_public()
        return _json(
            self,
            {
                "version": VERSION,
                "build": f"v{VERSION}",
                "enabled": manager.enabled,
                "remaining_seconds": manager.enabled_remaining,
                "pending_sessions": manager.pending_count,
                "max_pending_sessions": manager.max_pending_sessions,
                "window_seconds": manager.enable_window_seconds,
                "qr_lifetime_seconds": manager.qr_lifetime_seconds,
                "active": active,
                "history": [entry.as_dict() for entry in manager.history],
            },
        )


class AdminSettingsView(HomeAssistantView):
    """Read and update all runtime security settings from the admin panel."""

    url = "/api/secure_qr_login/admin/settings"
    name = "api:secure_qr_login:admin_settings"
    requires_auth = True

    async def get(self, request: web.Request) -> web.Response:
        if rejected := _require_admin(self, request):
            return rejected

        manager = _manager(request)
        if manager is None:
            return _json(self, {"error": "not_ready"}, 503)

        users = await request.app["hass"].auth.async_get_users()
        user_options = [
            {"id": user.id, "name": user.name or user.id}
            for user in users
            if user.is_active and not user.system_generated
        ]

        notify_domain = request.app["hass"].services.async_services().get("notify", {})
        notify_options = sorted(notify_domain)

        cf_country = (request.headers.get("CF-IPCountry") or "").upper().strip()
        return _json(
            self,
            {
                "values": {
                    CONF_ENABLE_WINDOW_SECONDS: manager.enable_window_seconds,
                    CONF_QR_LIFETIME_SECONDS: manager.qr_lifetime_seconds,
                    CONF_MAX_PENDING_SESSIONS: manager.max_pending_sessions,
                    CONF_HISTORY_LIMIT: manager.history_limit,
                    CONF_ALLOWED_USER_IDS: sorted(manager.allowed_user_ids),
                    CONF_NOTIFY_SERVICES: manager.notify_services,
                    CONF_NOTIFY_ON_APPROVED: manager.notify_on_approved,
                    CONF_NOTIFY_ON_DENIED: manager.notify_on_denied,
                    CONF_ALLOWED_COUNTRIES: sorted(manager.allowed_countries),
                    CONF_ALLOW_PRIVATE_NETWORKS: manager.allow_private_networks,
                },
                "users": user_options,
                "notify_services": notify_options,
                "country_codes": sorted(ISO_COUNTRY_CODES),
                "geoip": {
                    "source": "Cloudflare CF-IPCountry",
                    "header_present": bool(cf_country),
                    "current_country": cf_country or None,
                    "cf_ray_present": bool(request.headers.get("CF-Ray")),
                },
            },
        )

    async def post(self, request: web.Request) -> web.Response:
        if rejected := _reject_cross_origin(self, request):
            return rejected
        if rejected := _require_admin(self, request):
            return rejected

        manager = _manager(request)
        if manager is None:
            return _json(self, {"error": "not_ready"}, 503)

        payload = await _json_body(request)
        if payload is None:
            return _json(self, {"error": "invalid_json"}, 400)

        enable_window = _validate_int(
            payload,
            CONF_ENABLE_WINDOW_SECONDS,
            MIN_ENABLE_WINDOW_SECONDS,
            MAX_ENABLE_WINDOW_SECONDS,
        )
        qr_lifetime = _validate_int(
            payload,
            CONF_QR_LIFETIME_SECONDS,
            MIN_QR_LIFETIME_SECONDS,
            MAX_QR_LIFETIME_SECONDS,
        )
        max_pending = _validate_int(
            payload,
            CONF_MAX_PENDING_SESSIONS,
            MIN_MAX_PENDING_SESSIONS,
            MAX_MAX_PENDING_SESSIONS,
        )
        history_limit = _validate_int(
            payload,
            CONF_HISTORY_LIMIT,
            MIN_HISTORY_LIMIT,
            MAX_HISTORY_LIMIT,
        )

        allowed_users = _validate_string_list(
            payload.get(CONF_ALLOWED_USER_IDS),
            maximum=128,
        )
        notify_services = _validate_string_list(
            payload.get(CONF_NOTIFY_SERVICES),
            maximum=128,
        )
        countries = _validate_string_list(
            payload.get(CONF_ALLOWED_COUNTRIES),
            maximum=249,
        )

        notify_approved = payload.get(CONF_NOTIFY_ON_APPROVED)
        notify_denied = payload.get(CONF_NOTIFY_ON_DENIED)
        allow_private = payload.get(CONF_ALLOW_PRIVATE_NETWORKS)

        if None in (
            enable_window,
            qr_lifetime,
            max_pending,
            history_limit,
            allowed_users,
            notify_services,
            countries,
        ):
            return _json(self, {"error": "invalid_settings"}, 400)

        if not all(
            isinstance(value, bool)
            for value in (notify_approved, notify_denied, allow_private)
        ):
            return _json(self, {"error": "invalid_settings"}, 400)

        available_users = {
            user.id
            for user in await request.app["hass"].auth.async_get_users()
            if user.is_active and not user.system_generated
        }
        if not set(allowed_users).issubset(available_users):
            return _json(self, {"error": "invalid_user"}, 400)

        available_notify = set(
            request.app["hass"].services.async_services().get("notify", {})
        )
        if not set(notify_services).issubset(available_notify):
            return _json(self, {"error": "invalid_notify_service"}, 400)

        normalized_countries: list[str] = []
        for item in countries:
            code = item.upper().strip()
            if code not in ISO_COUNTRY_CODES:
                return _json(self, {"error": "invalid_country_code"}, 400)
            if code not in normalized_countries:
                normalized_countries.append(code)

        options = dict(manager.entry.options)
        options.update(
            {
                CONF_ENABLE_WINDOW_SECONDS: enable_window,
                CONF_QR_LIFETIME_SECONDS: qr_lifetime,
                CONF_MAX_PENDING_SESSIONS: max_pending,
                CONF_HISTORY_LIMIT: history_limit,
                CONF_ALLOWED_USER_IDS: allowed_users,
                CONF_NOTIFY_SERVICES: notify_services,
                CONF_NOTIFY_ON_APPROVED: notify_approved,
                CONF_NOTIFY_ON_DENIED: notify_denied,
                CONF_ALLOWED_COUNTRIES: normalized_countries,
                CONF_ALLOW_PRIVATE_NETWORKS: allow_private,
            }
        )

        await manager.async_update_settings(options)
        return _json(self, {"status": "saved"})


class AdminWindowView(HomeAssistantView):
    url = "/api/secure_qr_login/admin/window"
    name = "api:secure_qr_login:admin_window"
    requires_auth = True

    async def post(self, request: web.Request) -> web.Response:
        if rejected := _reject_cross_origin(self, request):
            return rejected
        if rejected := _require_admin(self, request):
            return rejected

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
            {
                "enabled": manager.enabled,
                "remaining_seconds": manager.enabled_remaining,
            },
        )


class AdminRevokeView(HomeAssistantView):
    """Revoke one refresh token created by this integration."""

    url = "/api/secure_qr_login/admin/revoke"
    name = "api:secure_qr_login:admin_revoke"
    requires_auth = True

    async def post(self, request: web.Request) -> web.Response:
        if rejected := _reject_cross_origin(self, request):
            return rejected
        if rejected := _require_admin(self, request):
            return rejected

        manager = _manager(request)
        if manager is None:
            return _json(self, {"error": "not_ready"}, 503)

        payload = await _json_body(request)
        if payload is None:
            return _json(self, {"error": "invalid_json"}, 400)

        login_id = _clean(payload.get("login_id"), 128)
        if not login_id:
            return _json(self, {"error": "invalid_login_id"}, 400)

        actor = request["hass_user"]
        revoked = await manager.async_revoke_login(
            login_id,
            actor_user_name=actor.name or actor.id,
        )
        if not revoked:
            return _json(self, {"error": "active_login_not_found"}, 404)
        return _json(self, {"status": "revoked"})


class AdminRevokeAllView(HomeAssistantView):
    """Revoke every QR-created token and close the current security window."""

    url = "/api/secure_qr_login/admin/revoke-all"
    name = "api:secure_qr_login:admin_revoke_all"
    requires_auth = True

    async def post(self, request: web.Request) -> web.Response:
        if rejected := _reject_cross_origin(self, request):
            return rejected
        if rejected := _require_admin(self, request):
            return rejected

        manager = _manager(request)
        if manager is None:
            return _json(self, {"error": "not_ready"}, 503)

        actor = request["hass_user"]
        count = await manager.async_revoke_all_logins(
            actor_user_name=actor.name or actor.id,
        )
        return _json(self, {"status": "revoked", "count": count})


class AdminClearHistoryView(HomeAssistantView):
    """Clear only audit history; active sessions/tokens are untouched."""

    url = "/api/secure_qr_login/admin/clear-history"
    name = "api:secure_qr_login:admin_clear_history"
    requires_auth = True

    async def post(self, request: web.Request) -> web.Response:
        if rejected := _reject_cross_origin(self, request):
            return rejected
        if rejected := _require_admin(self, request):
            return rejected

        manager = _manager(request)
        if manager is None:
            return _json(self, {"error": "not_ready"}, 503)

        await manager.async_clear_history()
        return _json(self, {"status": "cleared"})


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
        "app.css": "text/css",
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
        AdminSettingsView(),
        AdminWindowView(),
        AdminRevokeView(),
        AdminRevokeAllView(),
        AdminClearHistoryView(),
        StartPageView(),
        ApprovePageView(),
        AdminPageView(),
        StaticView(),
    ):
        hass.http.register_view(view)
