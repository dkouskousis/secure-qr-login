"""Lifecycle, policy and session manager for Secure QR Login."""

from __future__ import annotations

from datetime import timedelta
import time
from typing import Callable

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.event import async_call_later, async_track_time_interval

from .auth import async_revoke_refresh_token
from .const import (
    CONF_ALLOWED_USER_IDS,
    CONF_ENABLE_WINDOW_SECONDS,
    CONF_HISTORY_LIMIT,
    CONF_MAX_PENDING_SESSIONS,
    CONF_NOTIFY_ON_APPROVED,
    CONF_NOTIFY_ON_DENIED,
    CONF_NOTIFY_SERVICES,
    CONF_QR_LIFETIME_SECONDS,
    DEFAULT_ALLOWED_USER_IDS,
    DEFAULT_ENABLE_WINDOW_SECONDS,
    DEFAULT_HISTORY_LIMIT,
    DEFAULT_MAX_PENDING_SESSIONS,
    DEFAULT_NOTIFY_ON_APPROVED,
    DEFAULT_NOTIFY_ON_DENIED,
    DEFAULT_NOTIFY_SERVICES,
    DEFAULT_QR_LIFETIME_SECONDS,
    MAX_ENABLE_WINDOW_SECONDS,
    MAX_HISTORY_LIMIT,
    MAX_MAX_PENDING_SESSIONS,
    MAX_QR_LIFETIME_SECONDS,
    MIN_ENABLE_WINDOW_SECONDS,
    MIN_HISTORY_LIMIT,
    MIN_MAX_PENDING_SESSIONS,
    MIN_QR_LIFETIME_SECONDS,
)
from .models import ActiveLogin, AuditEntry, LoginSession
from .notifications import async_send_security_notification
from .storage import PersistentSecurityStore


class SecureQrLoginManager:
    """Own the security window, policy, in-flight sessions and persistent history."""

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        self.hass = hass
        self.entry = entry
        self.sessions: dict[str, LoginSession] = {}
        self.store = PersistentSecurityStore(hass)
        self.enabled_until = 0.0
        self._disable_unsub: Callable[[], None] | None = None
        self._listeners: set[Callable[[], None]] = set()
        self._cleanup_unsub = async_track_time_interval(
            hass, self._async_cleanup, timedelta(seconds=15)
        )

    async def async_initialize(self) -> None:
        """Load persistent metadata and revoke orphaned unconsumed tokens."""
        await self.store.async_load(self.history_limit)
        changed = False

        for login_id, record in list(self.store.active.items()):
            refresh_token = self.hass.auth.async_get_refresh_token(
                record.refresh_token_id
            )
            if refresh_token is None:
                self.store.active.pop(login_id, None)
                self.store.history.insert(
                    0,
                    AuditEntry(
                        event="active_token_missing",
                        session_id=login_id,
                        user_id=record.user_id,
                        user_name=record.user_name,
                    ),
                )
                changed = True
                continue

            # A token issued before a restart but never delivered is an orphan.
            # Fail closed: revoke it before accepting any new QR requests.
            if not record.delivered:
                await async_revoke_refresh_token(self.hass, refresh_token)
                self.store.active.pop(login_id, None)
                self.store.history.insert(
                    0,
                    AuditEntry(
                        event="orphaned_token_revoked",
                        session_id=login_id,
                        client_ip=record.client_ip,
                        user_id=record.user_id,
                        user_name=record.user_name,
                    ),
                )
                changed = True

        if changed:
            del self.store.history[self.history_limit :]
            await self.store.async_save(self.history_limit)

    def _bounded_int(self, key: str, default: int, low: int, high: int) -> int:
        try:
            value = int(self.entry.options.get(key, default))
        except (TypeError, ValueError):
            value = default
        return max(low, min(high, value))

    @property
    def enable_window_seconds(self) -> int:
        return self._bounded_int(
            CONF_ENABLE_WINDOW_SECONDS,
            DEFAULT_ENABLE_WINDOW_SECONDS,
            MIN_ENABLE_WINDOW_SECONDS,
            MAX_ENABLE_WINDOW_SECONDS,
        )

    @property
    def qr_lifetime_seconds(self) -> int:
        return self._bounded_int(
            CONF_QR_LIFETIME_SECONDS,
            DEFAULT_QR_LIFETIME_SECONDS,
            MIN_QR_LIFETIME_SECONDS,
            MAX_QR_LIFETIME_SECONDS,
        )

    @property
    def max_pending_sessions(self) -> int:
        return self._bounded_int(
            CONF_MAX_PENDING_SESSIONS,
            DEFAULT_MAX_PENDING_SESSIONS,
            MIN_MAX_PENDING_SESSIONS,
            MAX_MAX_PENDING_SESSIONS,
        )

    @property
    def history_limit(self) -> int:
        return self._bounded_int(
            CONF_HISTORY_LIMIT,
            DEFAULT_HISTORY_LIMIT,
            MIN_HISTORY_LIMIT,
            MAX_HISTORY_LIMIT,
        )

    @property
    def allowed_user_ids(self) -> set[str]:
        raw = self.entry.options.get(CONF_ALLOWED_USER_IDS, DEFAULT_ALLOWED_USER_IDS)
        return {str(item) for item in raw if isinstance(item, str)}

    @property
    def notify_services(self) -> list[str]:
        raw = self.entry.options.get(CONF_NOTIFY_SERVICES, DEFAULT_NOTIFY_SERVICES)
        return [str(item) for item in raw if isinstance(item, str)]

    @property
    def notify_on_approved(self) -> bool:
        return bool(
            self.entry.options.get(
                CONF_NOTIFY_ON_APPROVED,
                DEFAULT_NOTIFY_ON_APPROVED,
            )
        )

    @property
    def notify_on_denied(self) -> bool:
        return bool(
            self.entry.options.get(
                CONF_NOTIFY_ON_DENIED,
                DEFAULT_NOTIFY_ON_DENIED,
            )
        )

    @property
    def enabled(self) -> bool:
        return time.time() < self.enabled_until

    @property
    def enabled_remaining(self) -> int:
        return max(0, int(self.enabled_until - time.time()))

    @property
    def pending_count(self) -> int:
        now = time.time()
        return sum(
            1
            for session in self.sessions.values()
            if session.status == "pending" and not session.expired(now)
        )

    @property
    def history(self) -> list[AuditEntry]:
        return self.store.history

    @property
    def active_logins(self) -> dict[str, ActiveLogin]:
        return self.store.active

    def user_allowed(self, user) -> bool:
        """Return whether this HA user may approve a QR login for themselves."""
        if user is None or not user.is_active or user.system_generated:
            return False
        allowlist = self.allowed_user_ids
        return not allowlist or user.id in allowlist

    async def async_record(self, entry: AuditEntry) -> None:
        """Persist a credential-free security event."""
        await self.store.async_add_history(entry, self.history_limit)
        self._notify()

    async def async_enable(self) -> None:
        """Open a fresh bounded login window."""
        if self._disable_unsub:
            self._disable_unsub()
            self._disable_unsub = None

        await self.async_purge_sessions(event="window_reset")
        duration = self.enable_window_seconds
        self.enabled_until = time.time() + duration
        await self.async_record(AuditEntry(event="window_enabled", session_id=""))

        @callback
        def auto_disable(_now) -> None:
            self.hass.async_create_task(self.async_disable("window_expired"))

        self._disable_unsub = async_call_later(self.hass, duration, auto_disable)
        self._notify()

    async def async_disable(self, event: str = "window_disabled") -> None:
        """Close the feature and invalidate every unconsumed request."""
        if self._disable_unsub:
            self._disable_unsub()
            self._disable_unsub = None
        self.enabled_until = 0.0
        await self.async_purge_sessions(event=event)
        await self.async_record(AuditEntry(event=event, session_id=""))
        self._notify()

    async def async_track_issued(self, session: LoginSession) -> None:
        """Persist token metadata before reporting approval success.

        This guarantees that a restart between approval and credential delivery
        cannot leave an untracked valid refresh token behind.
        """
        if session.refresh_token is None:
            raise RuntimeError("Cannot track a session without a refresh token")

        record = ActiveLogin(
            login_id=session.session_id,
            refresh_token_id=session.refresh_token.id,
            user_id=session.approved_user_id,
            user_name=session.approved_user_name,
            client_ip=session.client_ip,
            user_agent=session.user_agent,
            approved_at=session.approved_at,
            delivered=False,
        )
        await self.store.async_upsert_active(record, self.history_limit)

    async def async_mark_consumed(self, session: LoginSession) -> None:
        """Mark a token as delivered only after device-secret verification."""
        record = self.store.active.get(session.session_id)
        if record is None:
            raise RuntimeError("Approved token metadata is missing")
        record.delivered = True
        record.delivered_at = time.time()
        await self.store.async_upsert_active(record, self.history_limit)
        await self.async_record(
            AuditEntry(
                event="credentials_consumed",
                session_id=session.session_id,
                client_ip=session.client_ip,
                user_id=session.approved_user_id,
                user_name=session.approved_user_name,
            )
        )

    async def async_revoke_login(
        self,
        login_id: str,
        *,
        actor_user_name: str = "",
    ) -> bool:
        """Revoke one QR-created HA refresh token by its safe login id."""
        record = self.store.active.get(login_id)
        if record is None or not record.delivered:
            return False

        refresh_token = self.hass.auth.async_get_refresh_token(
            record.refresh_token_id
        )
        if refresh_token is not None:
            await async_revoke_refresh_token(self.hass, refresh_token)

        await self.store.async_remove_active(login_id, self.history_limit)
        await self.async_record(
            AuditEntry(
                event="token_revoked",
                session_id=login_id,
                client_ip=record.client_ip,
                user_id=record.user_id,
                user_name=record.user_name,
                detail=f"revoked_by={actor_user_name}" if actor_user_name else "",
            )
        )
        return True

    async def async_get_active_public(self) -> list[dict]:
        """Return active QR logins and prune tokens revoked elsewhere."""
        changed = False
        result: list[dict] = []

        for login_id, record in list(self.store.active.items()):
            refresh_token = self.hass.auth.async_get_refresh_token(
                record.refresh_token_id
            )
            if refresh_token is None:
                self.store.active.pop(login_id, None)
                self.store.history.insert(
                    0,
                    AuditEntry(
                        event="token_revoked_externally",
                        session_id=login_id,
                        client_ip=record.client_ip,
                        user_id=record.user_id,
                        user_name=record.user_name,
                    ),
                )
                changed = True
                continue
            if record.delivered:
                result.append(record.as_public())

        if changed:
            del self.store.history[self.history_limit :]
            await self.store.async_save(self.history_limit)

        result.sort(key=lambda item: item["delivered_at"], reverse=True)
        return result

    async def async_notify_result(
        self,
        event: str,
        session: LoginSession,
        account: str,
    ) -> None:
        if event == "approved" and not self.notify_on_approved:
            return
        if event == "denied" and not self.notify_on_denied:
            return
        await async_send_security_notification(
            self.hass,
            self.notify_services,
            event=event,
            account=account,
            client_ip=session.client_ip,
            user_agent=session.user_agent,
        )

    async def async_purge_sessions(self, event: str) -> None:
        """Remove in-flight sessions and revoke every undelivered token."""
        for session in list(self.sessions.values()):
            if session.refresh_token is not None and not session.consumed:
                await async_revoke_refresh_token(self.hass, session.refresh_token)
                self.store.active.pop(session.session_id, None)
            await self.async_record(
                AuditEntry(
                    event=event,
                    session_id=session.session_id,
                    client_ip=session.client_ip,
                    user_id=session.approved_user_id,
                    user_name=session.approved_user_name,
                )
            )
        self.sessions.clear()
        await self.store.async_save(self.history_limit)

    async def _async_cleanup(self, _now=None) -> None:
        now = time.time()
        expired = [
            sid for sid, session in self.sessions.items() if session.expired(now)
        ]
        for sid in expired:
            session = self.sessions.pop(sid)
            if session.refresh_token is not None and not session.consumed:
                await async_revoke_refresh_token(self.hass, session.refresh_token)
                self.store.active.pop(session.session_id, None)
            await self.async_record(
                AuditEntry(
                    event="session_expired",
                    session_id=session.session_id,
                    client_ip=session.client_ip,
                    user_id=session.approved_user_id,
                    user_name=session.approved_user_name,
                )
            )

        if self.enabled_until and now >= self.enabled_until:
            await self.async_disable("window_expired")

    async def async_shutdown(self) -> None:
        if self._disable_unsub:
            self._disable_unsub()
            self._disable_unsub = None
        if self._cleanup_unsub:
            self._cleanup_unsub()
        # Delivered refresh tokens remain valid across integration reloads.
        await self.async_purge_sessions(event="integration_unloaded")

    def new_session_expiry(self) -> float:
        """Never allow a request to outlive the currently open window."""
        return self.enabled_until

    @callback
    def add_listener(self, listener: Callable[[], None]) -> Callable[[], None]:
        self._listeners.add(listener)

        @callback
        def remove() -> None:
            self._listeners.discard(listener)

        return remove

    @callback
    def _notify(self) -> None:
        for listener in tuple(self._listeners):
            listener()
