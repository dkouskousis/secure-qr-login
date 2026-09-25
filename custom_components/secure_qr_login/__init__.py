"""Secure QR Login integration."""

from __future__ import annotations

from homeassistant.components import frontend
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant

from .const import DOMAIN, PANEL_URL_PATH, PLATFORMS
from .manager import SecureQrLoginManager
from .views import register_views

_VIEWS_REGISTERED = f"{DOMAIN}_views_registered"


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up Secure QR Login from a config entry."""
    manager = SecureQrLoginManager(hass, entry)
    await manager.async_initialize()
    hass.data[DOMAIN] = manager

    if not hass.data.get(_VIEWS_REGISTERED):
        register_views(hass)
        hass.data[_VIEWS_REGISTERED] = True

    frontend.async_register_built_in_panel(
        hass,
        component_name="iframe",
        sidebar_title="QR Login",
        sidebar_icon="mdi:qrcode-scan",
        frontend_url_path=PANEL_URL_PATH,
        config={"url": "/secure_qr_login/admin"},
        require_admin=True,
        update=True,
    )

    entry.async_on_unload(entry.add_update_listener(async_reload_entry))
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_reload_entry(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Reload when security options change."""
    await hass.config_entries.async_reload(entry.entry_id)


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload Secure QR Login."""
    ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if not ok:
        return False

    manager = hass.data.pop(DOMAIN, None)
    if manager is not None:
        await manager.async_shutdown()

    frontend.async_remove_panel(hass, PANEL_URL_PATH, warn_if_unknown=False)
    return True
