"""Persistent credential-free state for Secure QR Login."""

from __future__ import annotations

from typing import Any

from homeassistant.core import HomeAssistant
from homeassistant.helpers.storage import Store

from .const import STORAGE_KEY, STORAGE_VERSION
from .models import ActiveLogin, AuditEntry


class PersistentSecurityStore:
    """Persist history and revocation metadata without storing credentials."""

    def __init__(self, hass: HomeAssistant) -> None:
        self._store: Store[dict[str, Any]] = Store(
            hass,
            STORAGE_VERSION,
            STORAGE_KEY,
        )
        self.history: list[AuditEntry] = []
        self.active: dict[str, ActiveLogin] = {}

    async def async_load(self, history_limit: int) -> None:
        data = await self._store.async_load() or {}
        self.history = [
            AuditEntry.from_dict(item)
            for item in data.get("history", [])
            if isinstance(item, dict)
        ][:history_limit]

        active: dict[str, ActiveLogin] = {}
        for item in data.get("active", []):
            if not isinstance(item, dict):
                continue
            record = ActiveLogin.from_storage(item)
            if record.login_id and record.refresh_token_id:
                active[record.login_id] = record
        self.active = active

    async def async_save(self, history_limit: int) -> None:
        """Write credential-free state atomically using HA's storage helper."""
        await self._store.async_save(
            {
                "history": [entry.as_dict() for entry in self.history[:history_limit]],
                "active": [record.as_storage() for record in self.active.values()],
            }
        )

    async def async_add_history(
        self,
        entry: AuditEntry,
        history_limit: int,
    ) -> None:
        self.history.insert(0, entry)
        del self.history[history_limit:]
        await self.async_save(history_limit)

    async def async_upsert_active(
        self,
        record: ActiveLogin,
        history_limit: int,
    ) -> None:
        self.active[record.login_id] = record
        await self.async_save(history_limit)

    async def async_remove_active(
        self,
        login_id: str,
        history_limit: int,
    ) -> ActiveLogin | None:
        record = self.active.pop(login_id, None)
        await self.async_save(history_limit)
        return record
