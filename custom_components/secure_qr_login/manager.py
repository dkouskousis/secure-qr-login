"""Lifecycle and session manager for Secure QR Login."""

from __future__ import annotations

from collections import deque
from datetime import timedelta
import logging
import time
from typing import Callable

from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.event import async_call_later, async_track_time_interval

from .auth import async_revoke_refresh_token
from .const import ENABLE_WINDOW_SECONDS, SESSION_LIFETIME_SECONDS
from .models import AuditEntry, LoginSession

_LOGGER = logging.getLogger(__name__)


class SecureQrLoginManager:
    """Own the temporary security window and all in-flight sessions."""

    def __init__(self, hass: HomeAssistant) -> None:
        self.hass = hass
        self.sessions: dict[str, LoginSession] = {}
        self.audit: deque[AuditEntry] = deque(maxlen=50)
        self.enabled_until = 0.0
        self._disable_unsub: Callable[[], None] | None = None
        self._listeners: set[Callable[[], None]] = set()
        self._cleanup_unsub = async_track_time_interval(
            hass, self._async_cleanup, timedelta(seconds=15)
        )

    @property
    def enabled(self) -> bool:
        return time.time() < self.enabled_until

    @property
    def enabled_remaining(self) -> int:
        return max(0, int(self.enabled_until - time.time()))

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

    async def async_enable(self) -> None:
        """Open a fresh 3-minute login window."""
        if self._disable_unsub:
            self._disable_unsub()
            self._disable_unsub = None
        # A new window must not inherit stale requests from an older window.
        await self.async_purge_sessions(event="window_reset")
        self.enabled_until = time.time() + ENABLE_WINDOW_SECONDS
        self.audit.appendleft(AuditEntry(event="window_enabled", session_id=""))

        @callback
        def auto_disable(_now) -> None:
            self.hass.async_create_task(self.async_disable("window_expired"))

        self._disable_unsub = async_call_later(
            self.hass, ENABLE_WINDOW_SECONDS, auto_disable
        )
        self._notify()

    async def async_disable(self, event: str = "window_disabled") -> None:
        """Close the feature and invalidate every unconsumed session."""
        if self._disable_unsub:
            self._disable_unsub()
            self._disable_unsub = None
        self.enabled_until = 0.0
        await self.async_purge_sessions(event=event)
        self.audit.appendleft(AuditEntry(event=event, session_id=""))
        self._notify()

    async def async_purge_sessions(self, event: str) -> None:
        """Remove sessions and revoke tokens that were never consumed."""
        for session in list(self.sessions.values()):
            if session.refresh_token is not None and not session.consumed:
                await async_revoke_refresh_token(self.hass, session.refresh_token)
            self.audit.appendleft(
                AuditEntry(
                    event=event,
                    session_id=session.session_id,
                    client_ip=session.client_ip,
                    user_id=session.approved_user_id,
                    user_name=session.approved_user_name,
                )
            )
        self.sessions.clear()

    async def _async_cleanup(self, _now=None) -> None:
        now = time.time()
        expired = [sid for sid, session in self.sessions.items() if session.expired(now)]
        for sid in expired:
            session = self.sessions.pop(sid)
            if session.refresh_token is not None and not session.consumed:
                await async_revoke_refresh_token(self.hass, session.refresh_token)
            self.audit.appendleft(
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
        await self.async_purge_sessions(event="integration_unloaded")

    def new_session_expiry(self) -> float:
        """Never allow a session to outlive the currently open window."""
        return min(time.time() + SESSION_LIFETIME_SECONDS, self.enabled_until)
