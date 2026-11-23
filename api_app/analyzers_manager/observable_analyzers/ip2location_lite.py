# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging
import os
import tempfile
import zipfile
from io import BytesIO

import IP2Location
import requests
from django.conf import settings

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import (
    AnalyzerConfigurationException,
    AnalyzerRunException,
)
from api_app.models import PluginConfig

logger = logging.getLogger(__name__)

# https://www.ip2location.com/download?token={TOKEN}&file={CODE}
# Downloads are ZIP archives and, since May 2025, redirect to a presigned URL.
DOWNLOAD_URL = "https://www.ip2location.com/download"

# Official package code. https://lite.ip2location.com/faq lists
# DB11LITEBINIPV6 as "IP2Location LITE DB11 - IPV6 - BIN".
# The IPv6 BIN also answers IPv4 lookups.
DB11_LITE_IPV6_CODE = "DB11LITEBINIPV6"
DB11_LITE_IPV6_FILENAME = "IP2LOCATION-LITE-DB11.IPV6.BIN"

# Not published on the LITE FAQ (that page only lists the DB11 codes and says
# the package code is on the account Download page). This follows the DB11
# pattern (DB11LITEBINIPV6) from the documented IPv4 CSV code DBASNLITE, which
# downloads IP2LOCATION-LITE-ASN.CSV. Confirm DBASNLITEBINIPV6 in the account
# Download page before relying on the ASN refresh.
ASN_LITE_IPV6_CODE = "DBASNLITEBINIPV6"
ASN_LITE_IPV6_FILENAME = "IP2LOCATION-LITE-ASN.IPV6.BIN"

# LITE publishes on the 1st and the 15th. Refresh shortly after 00:00 UTC.
UPDATE_SCHEDULE = {
    "minute": "0",
    "hour": "2",
    "day_of_week": "*",
    "day_of_month": "1,15",
    "month_of_year": "*",
}

_MAX_BIN_BYTES = 1024 * 1024 * 1024
_UNAVAILABLE_PREFIXES = (
    "this parameter is unavailable",
    "invalid ip address",
    "ipv6 address missing in ipv4 bin",
)

DATABASES = (
    {
        "code": DB11_LITE_IPV6_CODE,
        "filename": DB11_LITE_IPV6_FILENAME,
        "required": True,
    },
    {
        "code": ASN_LITE_IPV6_CODE,
        "filename": ASN_LITE_IPV6_FILENAME,
        "required": False,
    },
)


def _database_path(filename: str) -> str:
    return os.path.join(str(settings.MEDIA_ROOT), filename)


def _is_unavailable(value) -> bool:
    if not isinstance(value, str):
        return False
    lowered = value.strip().lower()
    return any(lowered.startswith(prefix) for prefix in _UNAVAILABLE_PREFIXES)


def _clean_text(value):
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return value
    if _is_unavailable(value):
        return None
    text = str(value).strip()
    if not text or text == "-":
        return None
    return text


def _clean_float(value):
    cleaned = _clean_text(value)
    if cleaned is None:
        return None
    if isinstance(cleaned, (int, float)):
        return float(cleaned)
    try:
        return float(cleaned)
    except (TypeError, ValueError):
        return None


def _clean_asn(value):
    cleaned = _clean_text(value)
    if cleaned is None:
        return None
    if isinstance(cleaned, int):
        return cleaned
    text = str(cleaned).strip()
    if text.upper().startswith("AS"):
        text = text[2:]
    if text.isdigit():
        return int(text)
    return None


def _report_from_records(ip: str, geo, asn) -> dict:
    return {
        "ip": ip,
        "country_short": _clean_text(getattr(geo, "country_short", None)),
        "country_long": _clean_text(getattr(geo, "country_long", None)),
        "region": _clean_text(getattr(geo, "region", None)),
        "city": _clean_text(getattr(geo, "city", None)),
        "latitude": _clean_float(getattr(geo, "latitude", None)),
        "longitude": _clean_float(getattr(geo, "longitude", None)),
        "zip_code": _clean_text(getattr(geo, "zipcode", None)),
        "time_zone": _clean_text(getattr(geo, "timezone", None)),
        "asn": _clean_asn(getattr(asn, "asn", None)) if asn is not None else None,
        "as_name": _clean_text(getattr(asn, "as_name", None)) if asn is not None else None,
    }


class IP2LocationLITE(classes.ObservableAnalyzer):
    """Offline IP geolocation and ASN lookup with IP2Location LITE BIN files.

    This analyzer uses the IP2Location LITE database for IP geolocation
    (https://www.ip2location.com/database/lite).
    """

    def run(self):
        token = self._configured_token()
        paths = {}
        errors = []
        for database in DATABASES:
            path = _database_path(database["filename"])
            if not os.path.isfile(path):
                try:
                    self._download_database(database["code"], token, path)
                except AnalyzerRunException as exc:
                    if database["required"]:
                        raise
                    errors.append(str(exc))
                    continue
            paths[database["filename"]] = path

        try:
            geo = self._query(paths[DB11_LITE_IPV6_FILENAME], self.observable_name)
        except AnalyzerRunException:
            raise
        except Exception as exc:
            raise AnalyzerRunException(f"IP2Location LITE DB11 lookup failed: {exc}") from exc

        asn_record = None
        asn_path = paths.get(ASN_LITE_IPV6_FILENAME)
        if asn_path:
            try:
                asn_record = self._query(asn_path, self.observable_name)
            except Exception as exc:
                errors.append(f"IP2Location LITE ASN lookup failed: {exc}")

        report = _report_from_records(self.observable_name, geo, asn_record)
        # "-" means this range has no ASN. The long "unavailable" string means the
        # reader does not know this BIN's database type (8.11.0 fills asn only for DB26).
        if asn_record is not None and _is_unavailable(getattr(asn_record, "asn", None)):
            errors.append(
                "IP2Location LITE ASN BIN opened but the reader has no ASN field for it. "
                "IP2Location 8.11.0 fills asn and as_name for database type 26 (DB26). "
                "Confirm the LITE ASN IPv6 BIN from file code "
                f"{ASN_LITE_IPV6_CODE} is readable by that library."
            )
        self._record_errors(errors)
        return report

    @classmethod
    def update(cls) -> bool:
        token = cls._stored_token()
        if not token:
            logger.warning("IP2Location LITE download token is not configured; skipping database update")
            return False
        updated = True
        for database in DATABASES:
            try:
                cls._download_database(
                    database["code"],
                    token,
                    _database_path(database["filename"]),
                )
            except Exception:
                logger.exception("Failed to update IP2Location LITE database %s", database["code"])
                updated = False
        return updated

    def _configured_token(self) -> str:
        token = getattr(self, "_download_token", None)
        if not token:
            raise AnalyzerConfigurationException(
                "IP2Location LITE download token is not configured. "
                "Create a free account at https://www.ip2location.com/register?id=lite "
                "and copy the token from the Download page."
            )
        return token

    @classmethod
    def _stored_token(cls):
        try:
            configs = PluginConfig.objects.filter(
                parameter__python_module=cls.python_module,
                parameter__is_secret=True,
                parameter__name="download_token",
            )
        except Exception:
            logger.exception("Could not read the IP2Location LITE download token")
            return None
        for config in configs:
            if config.value:
                return config.value
        return None

    @staticmethod
    def _query(path: str, ip: str):
        reader = IP2Location.IP2Location(path)
        try:
            return reader.get_all(ip)
        finally:
            reader.close()

    def _record_errors(self, errors):
        if not errors:
            return
        for message in errors:
            logger.warning(message)
        report = getattr(self, "report", None)
        if report is not None and hasattr(report, "errors"):
            report.errors.extend(errors)
            report.save()

    @classmethod
    def _download_database(cls, file_code: str, token: str, destination: str) -> None:
        if not token:
            raise AnalyzerConfigurationException("IP2Location LITE download token is empty")
        logger.info("Downloading IP2Location LITE database %s", file_code)
        try:
            response = requests.get(
                DOWNLOAD_URL,
                params={"token": token, "file": file_code},
                timeout=(30, 180),
                allow_redirects=True,
            )
        except requests.RequestException as exc:
            raise AnalyzerRunException(f"IP2Location LITE download for {file_code} failed: {exc}") from exc
        if response.status_code >= 400:
            raise AnalyzerRunException(
                f"IP2Location LITE download for {file_code} returned HTTP {response.status_code}"
            )
        payload = response.content or b""
        if not payload.startswith(b"PK"):
            snippet = payload[:200].decode("utf-8", errors="replace").replace("\n", " ")
            raise AnalyzerRunException(
                f"IP2Location LITE download for {file_code} did not return a ZIP archive: {snippet}"
            )
        bin_bytes = cls._read_bin_from_zip(file_code, payload)
        directory = os.path.dirname(destination) or "."
        os.makedirs(directory, exist_ok=True)
        temporary = None
        try:
            handle = tempfile.NamedTemporaryFile(dir=directory, suffix=".bin.part", delete=False)
            temporary = handle.name
            with handle:
                handle.write(bin_bytes)
            os.replace(temporary, destination)
        except Exception:
            if temporary and os.path.exists(temporary):
                os.remove(temporary)
            raise
        logger.info("Saved IP2Location LITE database %s to %s", file_code, destination)

    @staticmethod
    def _read_bin_from_zip(file_code: str, payload: bytes) -> bytes:
        try:
            archive = zipfile.ZipFile(BytesIO(payload))
        except zipfile.BadZipFile as exc:
            raise AnalyzerRunException(
                f"IP2Location LITE download for {file_code} is not a valid ZIP archive"
            ) from exc
        with archive:
            members = [
                info
                for info in archive.infolist()
                if not info.is_dir() and info.filename.lower().endswith(".bin")
            ]
            if not members:
                raise AnalyzerRunException(
                    f"IP2Location LITE archive for {file_code} does not contain a BIN file"
                )
            preferred = [info for info in members if "ipv6" in info.filename.lower()]
            chosen = preferred[0] if preferred else members[0]
            if chosen.file_size > _MAX_BIN_BYTES:
                raise AnalyzerRunException(
                    f"IP2Location LITE BIN {chosen.filename} is larger than {_MAX_BIN_BYTES} bytes"
                )
            return archive.read(chosen)
