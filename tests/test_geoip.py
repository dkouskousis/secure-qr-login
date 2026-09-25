"""Tests for privacy-preserving local GeoIP resolution."""

from custom_components.secure_qr_login.geoip import LocalGeoIPResolver


class FakeReader:
    """Minimal in-memory MMDB reader used to avoid network-bound tests."""

    def __init__(self, countries=None):
        self.countries = countries or {}
        self.closed = False

    def get(self, ip):
        code = self.countries.get(ip)
        if code is None:
            return None
        return {"country": {"iso_code": code}}

    def close(self):
        self.closed = True


async def test_local_geoip_resolves_public_ipv4_without_remote_api(hass) -> None:
    resolver = LocalGeoIPResolver(hass)
    resolver._reader = FakeReader({"8.8.8.8": "US"})

    result = await resolver.async_lookup_ip("8.8.8.8")

    assert result.country_code == "US"
    assert result.source == "local_database"
    assert result.reason == "resolved"


async def test_local_geoip_supports_ipv6(hass) -> None:
    resolver = LocalGeoIPResolver(hass)
    resolver._reader = FakeReader({"2606:4700:4700::1111": "US"})

    result = await resolver.async_lookup_ip("2606:4700:4700::1111")

    assert result.country_code == "US"
    assert result.source == "local_database"
    assert result.reason == "resolved"


async def test_private_ip_never_returns_a_country(hass) -> None:
    resolver = LocalGeoIPResolver(hass)

    result = await resolver.async_lookup_ip("192.168.1.50")

    assert result.country_code is None
    assert result.source == "local_network"
    assert result.reason == "private_network"


async def test_unknown_public_ip_fails_closed(hass) -> None:
    resolver = LocalGeoIPResolver(hass)
    resolver._reader = FakeReader()

    result = await resolver.async_lookup_ip("8.8.4.4")

    assert result.country_code is None
    assert result.reason == "country_unknown"


async def test_failed_update_keeps_existing_reader(hass, monkeypatch) -> None:
    resolver = LocalGeoIPResolver(hass)
    reader = FakeReader({"8.8.8.8": "US"})
    resolver._reader = reader
    resolver._database_release = "2000-01"

    async def fail_download(_year, _month):
        return False

    monkeypatch.setattr(resolver, "_async_download_release", fail_download)

    await resolver.async_initialize()

    assert resolver.database_ready
    assert resolver._reader is reader
