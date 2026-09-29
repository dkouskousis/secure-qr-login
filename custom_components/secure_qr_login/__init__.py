"""Secure QR Login integration."""

from __future__ import annotations

from homeassistant.components import frontend, panel_custom
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant

from .const import DOMAIN, PANEL_URL_PATH, PLATFORMS, VERSION
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

    # Register as a real Home Assistant custom panel, not an iframe.
    # The Android Companion App intentionally rejects external-auth requests
    # originating from iframes. A native custom panel receives the authenticated
    # `hass` object directly and can use hass.callApi() on every platform.
    await panel_custom.async_register_panel(
        hass,
        frontend_url_path=PANEL_URL_PATH,
        webcomponent_name="secure-qr-login-panel",
        sidebar_title="QR Login",
        sidebar_icon="mdi:qrcode-scan",
        module_url=f"/secure_qr_login/static/panel.js?v={VERSION}",
        embed_iframe=False,
        trust_external=False,
        require_admin=True,
        handle_safe_area=False,
    )

    # Settings are read dynamically from entry.options and are updated by the
    # admin API. Avoiding a config-entry reload prevents unnecessary panel
    # interruptions and keeps already-delivered QR sessions untouched.
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


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
