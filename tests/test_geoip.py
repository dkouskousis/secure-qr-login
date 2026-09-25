"""Tests for the local privacy-preserving GeoIP resolver."""

from custom_components.secure_qr_login.const import ISO_COUNTRY_CODES
from custom_components.secure_qr_login.geoip import LocalGeoIPResolver


async def test_local_geoip_database_loads_and_resolves_public_ipv4(hass) -> None:
    resolver = LocalGeoIPResolver(hass)
    await resolver.async_initialize()

    assert resolver.database_ready

    result = await resolver.async_lookup_ip("8.8.8.8")
    assert result.country_code in ISO_COUNTRY_CODES
    assert result.source == "local_database"
    assert result.reason == "resolved"


async def test_local_geoip_database_supports_ipv6(hass) -> None:
    resolver = LocalGeoIPResolver(hass)
    await resolver.async_initialize()

    result = await resolver.async_lookup_ip("2606:4700:4700::1111")
    assert result.country_code in ISO_COUNTRY_CODES
    assert result.source == "local_database"
    assert result.reason == "resolved"


async def test_private_ip_never_returns_a_country(hass) -> None:
    resolver = LocalGeoIPResolver(hass)

    result = await resolver.async_lookup_ip("192.168.1.50")
    assert result.country_code is None
    assert result.source == "local_network"
    assert result.reason == "private_network"
