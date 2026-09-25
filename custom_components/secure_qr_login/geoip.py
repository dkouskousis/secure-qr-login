"""Local GeoIP country resolution for Secure QR Login.

No client IP is sent to a remote lookup API. Country lookups use the local
GeoIP2Fast IPv4+IPv6 database bundled with the pinned Python dependency.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from ipaddress import ip_address
import logging

from geoip2fast import GeoIP2Fast
from hass_nabucasa import remote as nabu_remote

from homeassistant.core import HomeAssistant

_LOGGER = logging.getLogger(__name__)

_DATABASE_FILENAME = "geoip2fast-ipv6.dat.gz"


@dataclass(slots=True, frozen=True)
class GeoIPResult:
    """Result of resolving one client IP."""

    country_code: str | None
    source: str
    client_ip: str | None
    reason: str


class LocalGeoIPResolver:
    """Resolve public IPs locally without disclosing them to third parties."""

    def __init__(self, hass: HomeAssistant) -> None:
        self.hass = hass
        self._reader: GeoIP2Fast | None = None
        self._load_lock = asyncio.Lock()
        self._database_path: str | None = None
        self._source_info: str | None = None

    @property
    def database_ready(self) -> bool:
        return self._reader is not None

    @property
    def database_path(self) -> str | None:
        return self._database_path

    @property
    def source_info(self) -> str | None:
        return self._source_info

    async def async_initialize(self) -> None:
        """Load the local IPv4+IPv6 country database off the event loop."""
        await self._async_ensure_reader()

    async def _async_ensure_reader(self) -> GeoIP2Fast | None:
        if self._reader is not None:
            return self._reader

        async with self._load_lock:
            if self._reader is not None:
                return self._reader

            try:
                reader = await self.hass.async_add_executor_job(
                    self._load_reader
                )
            except Exception:
                _LOGGER.exception("Unable to load local GeoIP country database")
                return None

            self._reader = reader
            return reader

    def _load_reader(self) -> GeoIP2Fast:
        """Load the packaged database in an executor thread."""
        reader = GeoIP2Fast(
            geoip2fast_data_file=_DATABASE_FILENAME,
            verbose=False,
        )
        try:
            self._database_path = reader.get_database_path()
        except Exception:
            self._database_path = None

        try:
            info = reader.get_source_info()
            self._source_info = str(info)
        except Exception:
            self._source_info = None

        return reader

    async def async_lookup_ip(self, value: str | None) -> GeoIPResult:
        """Resolve a public client IP to a country code using the local DB."""
        if not value:
            return GeoIPResult(None, "local_database", None, "client_ip_missing")

        try:
            parsed = ip_address(value)
        except ValueError:
            return GeoIPResult(None, "local_database", None, "client_ip_invalid")

        normalized = str(parsed)
        if parsed.is_private or parsed.is_loopback or parsed.is_link_local:
            return GeoIPResult(None, "local_network", normalized, "private_network")

        reader = await self._async_ensure_reader()
        if reader is None:
            return GeoIPResult(
                None,
                "local_database",
                normalized,
                "database_unavailable",
            )

        try:
            result = await self.hass.async_add_executor_job(
                reader.lookup,
                normalized,
            )
        except Exception:
            _LOGGER.exception("Local GeoIP lookup failed")
            return GeoIPResult(
                None,
                "local_database",
                normalized,
                "lookup_failed",
            )

        if getattr(result, "is_private", False):
            return GeoIPResult(
                None,
                "local_network",
                normalized,
                "private_network",
            )

        country = str(getattr(result, "country_code", "") or "").upper()
        if len(country) != 2 or not country.isalpha() or country == "--":
            return GeoIPResult(
                None,
                "local_database",
                normalized,
                "country_unknown",
            )

        return GeoIPResult(country, "local_database", normalized, "resolved")


def is_nabu_casa_request() -> bool:
    """Return True when Home Assistant marks the request as Remote UI traffic."""
    return bool(nabu_remote.is_cloud_request.get())
