"""Diagnostics support for Secure QR Login.

Diagnostics intentionally exclude IP addresses, browser strings, user ids,
session ids, refresh-token ids and every authentication secret.
"""

from __future__ import annotations

from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant

from .const import DOMAIN, VERSION


async def async_get_config_entry_diagnostics(
    hass: HomeAssistant,
    entry: ConfigEntry,
) -> dict[str, Any]:
    """Return privacy-preserving diagnostics."""
    manager = hass.data.get(DOMAIN)
    if manager is None:
        return {
            "version": VERSION,
            "loaded": False,
            "options": _safe_options(entry.options),
        }

    history = manager.history
    event_counts: dict[str, int] = {}
    for item in history:
        event_counts[item.event] = event_counts.get(item.event, 0) + 1

    return {
        "version": VERSION,
        "loaded": True,
        "enabled": manager.enabled,
        "remaining_seconds": manager.enabled_remaining,
        "pending_session_count": manager.pending_count,
        "active_login_count": len(manager.active_logins),
        "history_entry_count": len(history),
        "history_event_counts": event_counts,
        "options": _safe_options(entry.options),
    }


def _safe_options(options: dict[str, Any]) -> dict[str, Any]:
    """Return settings without identifiers for people/devices."""
    return {
        "enable_window_seconds": options.get("enable_window_seconds", 180),
        "qr_lifetime_seconds": options.get("qr_lifetime_seconds", 10),
        "max_pending_sessions": options.get("max_pending_sessions", 3),
        "history_limit": options.get("history_limit", 100),
        "allowed_user_count": len(options.get("allowed_user_ids", [])),
        "notify_service_count": len(options.get("notify_services", [])),
        "notify_on_approved": options.get("notify_on_approved", True),
        "notify_on_denied": options.get("notify_on_denied", True),
        "allowed_country_count": len(options.get("allowed_countries", [])),
        "allow_private_networks": options.get("allow_private_networks", True),
        "geoip_source": "cloudflare_cf_ipcountry",
    }
