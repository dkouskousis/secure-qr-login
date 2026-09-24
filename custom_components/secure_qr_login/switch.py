"""Temporary enable/disable switch for Secure QR Login."""

from __future__ import annotations

from homeassistant.components.switch import SwitchEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN, ENABLE_WINDOW_SECONDS


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    manager = hass.data[DOMAIN]
    async_add_entities([SecureQrLoginSwitch(manager, entry.entry_id)])


class SecureQrLoginSwitch(SwitchEntity):
    """Switch that always turns itself off after three minutes."""

    _attr_name = "Secure QR Login"
    _attr_icon = "mdi:qrcode-scan"

    def __init__(self, manager, entry_id: str) -> None:
        self.manager = manager
        self._attr_unique_id = f"{entry_id}_temporary_enable"
        self._remove_listener = None

    @property
    def is_on(self) -> bool:
        return self.manager.enabled

    @property
    def extra_state_attributes(self):
        return {
            "remaining_seconds": self.manager.enabled_remaining,
            "window_seconds": ENABLE_WINDOW_SECONDS,
        }

    async def async_added_to_hass(self) -> None:
        @callback
        def changed() -> None:
            self.async_write_ha_state()
        self._remove_listener = self.manager.add_listener(changed)

    async def async_will_remove_from_hass(self) -> None:
        if self._remove_listener:
            self._remove_listener()

    async def _async_require_admin(self) -> None:
        """Only an authenticated administrator may open or close the window."""
        user_id = self._context.user_id
        if not user_id:
            raise HomeAssistantError("Secure QR Login can only be controlled by an administrator")
        user = await self.hass.auth.async_get_user(user_id)
        if user is None or not user.is_admin:
            raise HomeAssistantError("Administrator privileges are required")

    async def async_turn_on(self, **kwargs) -> None:
        await self._async_require_admin()
        await self.manager.async_enable()

    async def async_turn_off(self, **kwargs) -> None:
        await self._async_require_admin()
        await self.manager.async_disable()
