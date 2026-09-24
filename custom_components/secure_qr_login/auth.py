"""Home Assistant token issuance helpers."""

from __future__ import annotations

from homeassistant.core import HomeAssistant
from homeassistant.helpers.network import NoURLAvailableError, get_url

from .const import CLIENT_NAME
from .security import valid_remote_ip


def resolve_client_id(hass: HomeAssistant, preferred: str) -> str:
    """Return the frontend client_id used by HA refresh-token rotation."""
    if preferred:
        return preferred
    for prefer_external in (False, True):
        try:
            return get_url(hass, prefer_external=prefer_external).rstrip("/") + "/"
        except NoURLAvailableError:
            continue
    raise NoURLAvailableError("Unable to determine a Home Assistant URL")


async def async_issue_tokens(
    hass: HomeAssistant,
    user,
    *,
    client_id: str,
    remote_ip: str | None,
):
    """Create a normal HA refresh token and an access token for one user."""
    refresh_token = await hass.auth.async_create_refresh_token(
        user,
        client_id=resolve_client_id(hass, client_id),
        client_name=CLIENT_NAME,
    )
    access_token = hass.auth.async_create_access_token(
        refresh_token,
        remote_ip=valid_remote_ip(remote_ip),
    )
    expires_in = int(refresh_token.access_token_expiration.total_seconds())
    return refresh_token, access_token, expires_in


async def async_revoke_refresh_token(hass: HomeAssistant, refresh_token) -> None:
    """Revoke an issued token that was never delivered to its target device."""
    if refresh_token is None:
        return
    hass.auth.async_remove_refresh_token(refresh_token)
