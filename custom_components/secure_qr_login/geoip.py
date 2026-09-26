"""Privacy-preserving local GeoIP resolution.

The resolver never sends client IP addresses to a remote lookup API.

Country data comes from DB-IP Country Lite (CC BY 4.0) in MMDB format.
The database is downloaded locally and refreshed monthly. Home Assistant /
Nabu Casa provides the accepted client IP through request.remote; this module
only performs an offline IP -> country lookup on that already-accepted value.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from functools import partial
import gzip
from ipaddress import ip_address
import json
import logging
import os
from pathlib import Path

from aiohttp import ClientError, ClientTimeout
from hass_nabucasa import remote as nabu_remote
import maxminddb

from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.event import async_track_time_interval

from .const import DOMAIN, ISO_COUNTRY_CODES

_LOGGER = logging.getLogger(__name__)

_DB_FILENAME = "dbip-country-lite.mmdb"
_METADATA_FILENAME = "dbip-country-lite.json"
_DOWNLOAD_TEMPLATE = (
    "https://download.db-ip.com/free/dbip-country-lite-{year:04d}-{month:02d}.mmdb.gz"
)
_UPDATE_CHECK_INTERVAL = timedelta(hours=24)
_DOWNLOAD_TIMEOUT = ClientTimeout(total=120)
_MAX_ARCHIVE_BYTES = 25 * 1024 * 1024
_MAX_DATABASE_BYTES = 64 * 1024 * 1024


@dataclass(slots=True, frozen=True)
class GeoIPResult:
    """Result of resolving one client IP."""

    country_code: str | None
    source: str
    client_ip: str | None
    reason: str


@dataclass(slots=True, frozen=True)
class GeoIPUpdateResult:
    """Result of checking/updating the local country database."""

    success: bool
    updated: bool
    status: str
    release: str | None
    error: str | None
    attempted_at: str | None
    successful_at: str | None


UpdateCallback = Callable[[GeoIPUpdateResult, str], Awaitable[None]]


class LocalGeoIPResolver:
    """Resolve public IPs locally using a periodically refreshed MMDB file."""

    def __init__(
        self,
        hass: HomeAssistant,
        update_callback: UpdateCallback | None = None,
    ) -> None:
        self.hass = hass
        self._update_callback = update_callback
        self._reader = None
        self._load_lock = asyncio.Lock()
        self._directory = Path(hass.config.path(".storage", DOMAIN, "geoip"))
        self._database_path = self._directory / _DB_FILENAME
        self._metadata_path = self._directory / _METADATA_FILENAME
        self._database_release: str | None = None
        self._last_error: str | None = None
        self._last_update_attempt: str | None = None
        self._last_successful_update: str | None = None
        self._update_unsub = None

    @property
    def database_ready(self) -> bool:
        return self._reader is not None

    @property
    def database_path(self) -> str:
        return str(self._database_path)

    @property
    def database_release(self) -> str | None:
        return self._database_release

    @property
    def last_error(self) -> str | None:
        return self._last_error

    @property
    def last_update_attempt(self) -> str | None:
        return self._last_update_attempt

    @property
    def last_successful_update(self) -> str | None:
        return self._last_successful_update

    @property
    def source_info(self) -> str:
        return "DB-IP Country Lite (CC BY 4.0)"

    async def async_initialize(self) -> None:
        """Load an existing DB, refresh if needed, and start scheduled checks."""
        async with self._load_lock:
            if self._reader is None and self._database_path.exists():
                await self._async_open_existing_database()

            result = await self._async_refresh_if_needed_locked(force=False)

            if self._update_unsub is None:
                self._update_unsub = async_track_time_interval(
                    self.hass,
                    self._async_scheduled_refresh,
                    _UPDATE_CHECK_INTERVAL,
                )

        if result is not None:
            await self._async_notify_update(result, "automatic")

    async def async_force_update(self) -> GeoIPUpdateResult:
        """Manually check for and install the newest available DB release."""
        async with self._load_lock:
            if self._reader is None and self._database_path.exists():
                await self._async_open_existing_database()

            result = await self._async_refresh_if_needed_locked(force=True)

        # force=True always returns a result.
        assert result is not None
        return result

    async def async_shutdown(self) -> None:
        """Close the MMDB reader and stop scheduled update checks."""
        if self._update_unsub is not None:
            self._update_unsub()
            self._update_unsub = None

        reader = self._reader
        self._reader = None
        if reader is not None:
            await self.hass.async_add_executor_job(reader.close)

    async def _async_scheduled_refresh(self, _now=None) -> None:
        async with self._load_lock:
            result = await self._async_refresh_if_needed_locked(force=False)

        if result is not None:
            await self._async_notify_update(result, "automatic")

    async def _async_notify_update(
        self,
        result: GeoIPUpdateResult,
        trigger: str,
    ) -> None:
        if self._update_callback is None:
            return
        try:
            await self._update_callback(result, trigger)
        except Exception:
            _LOGGER.exception("GeoIP update callback failed")

    async def _async_open_existing_database(self) -> None:
        """Open the existing database off the event loop."""
        try:
            reader = await self.hass.async_add_executor_job(
                maxminddb.open_database,
                str(self._database_path),
            )
        except Exception as err:
            self._last_error = f"database_open_failed:{type(err).__name__}"
            await self._async_write_metadata()
            _LOGGER.warning("Unable to open local GeoIP database: %s", err)
            return

        old_reader = self._reader
        self._reader = reader
        if old_reader is not None:
            await self.hass.async_add_executor_job(old_reader.close)

        await self._async_load_metadata()

    async def _async_load_metadata(self) -> None:
        """Load non-sensitive database/update metadata."""
        data = await self.hass.async_add_executor_job(self._read_metadata)
        release = data.get("release")
        last_attempt = data.get("last_update_attempt")
        last_success = data.get("last_successful_update")
        last_error = data.get("last_error")

        self._database_release = release if isinstance(release, str) else None
        self._last_update_attempt = (
            last_attempt if isinstance(last_attempt, str) else None
        )
        self._last_successful_update = (
            last_success if isinstance(last_success, str) else None
        )
        self._last_error = last_error if isinstance(last_error, str) else None

    def _read_metadata(self) -> dict:
        try:
            value = json.loads(self._metadata_path.read_text(encoding="utf-8"))
        except (OSError, ValueError, TypeError):
            return {}
        return value if isinstance(value, dict) else {}

    async def _async_write_metadata(self) -> None:
        """Persist update metadata atomically without blocking the event loop."""
        await self.hass.async_add_executor_job(
            self._write_metadata,
            {
                "release": self._database_release,
                "source": "DB-IP Country Lite",
                "license": "CC BY 4.0",
                "last_update_attempt": self._last_update_attempt,
                "last_successful_update": self._last_successful_update,
                "last_error": self._last_error,
            },
        )

    def _write_metadata(self, data: dict) -> None:
        self._directory.mkdir(parents=True, exist_ok=True)
        metadata_tmp = self._metadata_path.with_suffix(".json.tmp")
        metadata_tmp.write_text(
            json.dumps(data, separators=(",", ":")),
            encoding="utf-8",
        )
        os.replace(metadata_tmp, self._metadata_path)

    async def _async_refresh_if_needed_locked(
        self,
        *,
        force: bool,
    ) -> GeoIPUpdateResult | None:
        target = self._current_release()

        if self._reader is not None and self._database_release == target:
            if not force:
                return None

            self._last_update_attempt = self._now_iso()
            self._last_error = None
            await self._async_write_metadata()
            return self._update_result(
                success=True,
                updated=False,
                status="up_to_date",
            )

        self._last_update_attempt = self._now_iso()
        await self._async_write_metadata()

        refreshed, error = await self._async_download_release(
            *map(int, target.split("-"))
        )
        if refreshed:
            await self._async_mark_update_success(target)
            return self._update_result(
                success=True,
                updated=True,
                status="updated",
            )

        previous = self._previous_month()
        previous_release = f"{previous.year:04d}-{previous.month:02d}"

        if self._database_release == previous_release and error == "not_found":
            self._last_error = None
            await self._async_write_metadata()
            return self._update_result(
                success=True,
                updated=False,
                status="latest_available",
            )

        if self._database_release != previous_release:
            previous_ok, previous_error = await self._async_download_release(
                previous.year,
                previous.month,
            )
            if previous_ok:
                await self._async_mark_update_success(previous_release)
                return self._update_result(
                    success=True,
                    updated=True,
                    status="updated",
                )
            if previous_error and previous_error != "not_found":
                error = previous_error

        self._last_error = error or "database_update_unavailable"
        await self._async_write_metadata()
        return self._update_result(
            success=False,
            updated=False,
            status="failed",
        )

    async def _async_mark_update_success(self, release: str) -> None:
        self._database_release = release
        self._last_successful_update = self._now_iso()
        self._last_error = None
        await self._async_write_metadata()
        await self._async_open_existing_database()

    @staticmethod
    def _now_iso() -> str:
        return datetime.now(UTC).isoformat()

    def _update_result(
        self,
        *,
        success: bool,
        updated: bool,
        status: str,
    ) -> GeoIPUpdateResult:
        return GeoIPUpdateResult(
            success=success,
            updated=updated,
            status=status,
            release=self._database_release,
            error=self._last_error,
            attempted_at=self._last_update_attempt,
            successful_at=self._last_successful_update,
        )

    @staticmethod
    def _current_release() -> str:
        now = datetime.now(UTC)
        return f"{now.year:04d}-{now.month:02d}"

    @staticmethod
    def _previous_month() -> datetime:
        now = datetime.now(UTC)
        first = now.replace(day=1)
        return (first - timedelta(days=1)).replace(day=1)

    async def _async_download_release(
        self,
        year: int,
        month: int,
    ) -> tuple[bool, str | None]:
        """Download, validate and atomically install one DB-IP monthly release."""
        url = _DOWNLOAD_TEMPLATE.format(year=year, month=month)
        release = f"{year:04d}-{month:02d}"

        # HomeAssistant.async_add_executor_job forwards positional arguments only.
        # Use partial so pathlib's keyword-only mkdir options are evaluated inside
        # the executor instead of being passed to Home Assistant itself.
        try:
            await self.hass.async_add_executor_job(
                partial(self._directory.mkdir, parents=True, exist_ok=True)
            )
        except OSError as err:
            code = f"database_directory_failed:{type(err).__name__}"
            _LOGGER.warning("Unable to create GeoIP storage directory: %s", err)
            return False, code

        archive_tmp = self._directory / f"{_DB_FILENAME}.{release}.gz.tmp"
        database_tmp = self._directory / f"{_DB_FILENAME}.{release}.tmp"

        session = async_get_clientsession(self.hass)
        try:
            async with session.get(url, timeout=_DOWNLOAD_TIMEOUT) as response:
                if response.status == 404:
                    return False, "not_found"
                response.raise_for_status()

                content_length = response.content_length
                if (
                    content_length is not None
                    and content_length > _MAX_ARCHIVE_BYTES
                ):
                    raise ValueError(
                        "GeoIP archive is larger than the allowed limit"
                    )

                archive_data = await response.read()
                if len(archive_data) > _MAX_ARCHIVE_BYTES:
                    raise ValueError("GeoIP archive exceeded the allowed limit")

                await self.hass.async_add_executor_job(
                    archive_tmp.write_bytes,
                    archive_data,
                )

            await self.hass.async_add_executor_job(
                self._install_downloaded_database,
                archive_tmp,
                database_tmp,
            )
        except (ClientError, TimeoutError, OSError, ValueError) as err:
            code = f"database_update_failed:{type(err).__name__}"
            _LOGGER.warning("Unable to update DB-IP GeoIP database: %s", err)
            return False, code
        except Exception as err:
            code = f"database_update_failed:{type(err).__name__}"
            _LOGGER.exception("Unexpected error updating DB-IP GeoIP database")
            return False, code
        finally:
            for path in (archive_tmp, database_tmp):
                try:
                    path.unlink(missing_ok=True)
                except OSError:
                    pass

        return True, None

    def _install_downloaded_database(
        self,
        archive_path: Path,
        database_tmp: Path,
    ) -> None:
        """Decompress, verify and atomically install the downloaded MMDB."""
        extracted = 0
        with gzip.open(archive_path, "rb") as source, database_tmp.open("wb") as target:
            while chunk := source.read(256 * 1024):
                extracted += len(chunk)
                if extracted > _MAX_DATABASE_BYTES:
                    raise ValueError("GeoIP database exceeded the allowed limit")
                target.write(chunk)

        reader = maxminddb.open_database(str(database_tmp))
        try:
            sample = reader.get("8.8.8.8")
            country = (
                sample.get("country", {}).get("iso_code")
                if isinstance(sample, dict)
                else None
            )
            if (
                not isinstance(country, str)
                or country.upper() not in ISO_COUNTRY_CODES
            ):
                raise ValueError("Downloaded GeoIP database failed validation")
        finally:
            reader.close()

        os.replace(database_tmp, self._database_path)

    async def async_lookup_ip(self, value: str | None) -> GeoIPResult:
        """Resolve a public client IP to a country using the local database."""
        if not value:
            return GeoIPResult(None, "local_database", None, "client_ip_missing")

        try:
            parsed = ip_address(value)
        except ValueError:
            return GeoIPResult(None, "local_database", None, "client_ip_invalid")

        normalized = str(parsed)
        if parsed.is_private or parsed.is_loopback or parsed.is_link_local:
            return GeoIPResult(None, "local_network", normalized, "private_network")

        if self._reader is None:
            await self.async_initialize()

        reader = self._reader
        if reader is None:
            return GeoIPResult(
                None,
                "local_database",
                normalized,
                "database_unavailable",
            )

        try:
            result = await self.hass.async_add_executor_job(reader.get, normalized)
        except Exception:
            _LOGGER.exception("Local GeoIP lookup failed")
            return GeoIPResult(
                None,
                "local_database",
                normalized,
                "lookup_failed",
            )

        country = (
            result.get("country", {}).get("iso_code")
            if isinstance(result, dict)
            else None
        )
        country = str(country or "").upper()

        if country not in ISO_COUNTRY_CODES:
            return GeoIPResult(
                None,
                "local_database",
                normalized,
                "country_unknown",
            )

        return GeoIPResult(country, "local_database", normalized, "resolved")


def is_nabu_casa_request() -> bool:
    """Return True when Home Assistant marks this as Remote UI traffic."""
    return bool(nabu_remote.is_cloud_request.get())
