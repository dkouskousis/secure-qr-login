"""Notification helpers for Secure QR Login."""

from __future__ import annotations

import logging

from homeassistant.core import HomeAssistant

_LOGGER = logging.getLogger(__name__)


async def async_send_security_notification(
    hass: HomeAssistant,
    notify_services: list[str],
    *,
    event: str,
    account: str,
    client_ip: str,
    user_agent: str,
) -> None:
    """Send a credential-free notification to configured HA notify services.

    No session ids, QR tokens, device secrets or HA tokens are ever included in
    notifications. Failures are logged but never alter authentication state.
    """
    if not notify_services:
        return

    if event == "approved":
        title = "Secure QR Login approved"
        message = f"QR login approved for {account} from {client_ip}."
    elif event == "denied":
        title = "Secure QR Login denied"
        message = f"QR login denied for {account} from {client_ip}."
    else:
        return

    for service in notify_services:
        if not isinstance(service, str) or not service:
            continue
        service_name = service.removeprefix("notify.")
        if not hass.services.has_service("notify", service_name):
            _LOGGER.warning("Configured notify service notify.%s no longer exists", service_name)
            continue
        try:
            await hass.services.async_call(
                "notify",
                service_name,
                {
                    "title": title,
                    "message": message,
                    "data": {
                        "tag": "secure_qr_login",
                        "group": "secure_qr_login",
                    },
                },
                blocking=False,
            )
        except Exception:  # Notification delivery must not affect auth state.
            _LOGGER.exception(
                "Failed sending Secure QR Login notification via notify.%s",
                service_name,
            )
