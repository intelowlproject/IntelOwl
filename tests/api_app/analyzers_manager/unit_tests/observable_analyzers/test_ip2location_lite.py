# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import os
import zipfile
from io import BytesIO
from types import SimpleNamespace
from unittest.mock import patch

from api_app.analyzers_manager.exceptions import AnalyzerRunException
from api_app.analyzers_manager.observable_analyzers.ip2location_lite import (
    ASN_LITE_IPV6_CODE,
    DB11_LITE_IPV6_CODE,
    DOWNLOAD_URL,
    IP2LocationLITE,
    _clean_asn,
    _clean_text,
    _report_from_records,
)
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)


def _record(**fields):
    defaults = {
        "country_short": "This parameter is unavailable in selected .BIN data file. Please upgrade data file.",
        "country_long": "This parameter is unavailable in selected .BIN data file. Please upgrade data file.",
        "region": "This parameter is unavailable in selected .BIN data file. Please upgrade data file.",
        "city": "This parameter is unavailable in selected .BIN data file. Please upgrade data file.",
        "latitude": "This parameter is unavailable in selected .BIN data file. Please upgrade data file.",
        "longitude": "This parameter is unavailable in selected .BIN data file. Please upgrade data file.",
        "zipcode": "-",
        "timezone": "This parameter is unavailable in selected .BIN data file. Please upgrade data file.",
        "asn": "This parameter is unavailable in selected .BIN data file. Please upgrade data file.",
        "as_name": "This parameter is unavailable in selected .BIN data file. Please upgrade data file.",
    }
    defaults.update(fields)
    return SimpleNamespace(**defaults)


class _FakeReader:
    def __init__(self, filename=None, mode="FILE_IO"):
        self.filename = str(filename or "")

    def get_all(self, ip):
        if "ASN" in os.path.basename(self.filename):
            return _record(asn="15169", as_name="Google LLC")
        return _record(
            country_short="US",
            country_long="United States of America",
            region="California",
            city="Mountain View",
            latitude="37.405992",
            longitude="-122.078515",
            zipcode="94043",
            timezone="-07:00",
        )

    @staticmethod
    def close():
        return None


def _zip_bytes(filename="IP2LOCATION-LITE-DB11.IPV6.BIN", payload=b"not-a-real-bin"):
    buffer = BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("README.TXT", "attribution")
        archive.writestr(filename, payload)
    return buffer.getvalue()


class _BinaryResponse:
    def __init__(self, content, status_code=200):
        self.content = content
        self.status_code = status_code


class IP2LocationLITETestCase(BaseAnalyzerTest):
    analyzer_class = IP2LocationLITE

    @staticmethod
    def get_mocked_response():
        return [
            patch(
                "api_app.analyzers_manager.observable_analyzers.ip2location_lite.os.path.isfile",
                return_value=True,
            ),
            patch(
                "api_app.analyzers_manager.observable_analyzers.ip2location_lite.IP2Location.IP2Location",
                _FakeReader,
            ),
        ]

    @classmethod
    def get_extra_config(cls) -> dict:
        return {"_download_token": "dummy-token"}

    def test_report_keeps_location_and_asn(self):
        report = _report_from_records(
            "8.8.8.8",
            _record(
                country_short="US",
                country_long="United States of America",
                region="California",
                city="Mountain View",
                latitude="37.405992",
                longitude="-122.078515",
                zipcode="94043",
                timezone="-07:00",
            ),
            _record(asn="AS15169", as_name="Google LLC"),
        )
        self.assertEqual(report["country_short"], "US")
        self.assertEqual(report["region"], "California")
        self.assertEqual(report["city"], "Mountain View")
        self.assertEqual(report["latitude"], 37.405992)
        self.assertEqual(report["longitude"], -122.078515)
        self.assertEqual(report["time_zone"], "-07:00")
        self.assertEqual(report["asn"], 15169)
        self.assertEqual(report["as_name"], "Google LLC")
        self.assertIsNone(_clean_text("-"))
        self.assertIsNone(_clean_asn("This parameter is unavailable in selected .BIN data file."))
        self.assertIsNone(_report_from_records("8.8.8.8", _record(), _record(asn="-", as_name="-"))["asn"])

    def test_ipv6_lookup_uses_the_same_reader(self):
        from api_app.analyzers_manager.models import AnalyzerConfig

        config = AnalyzerConfig.objects.get(name="IP2Location_LITE")
        patches = self.get_mocked_response()
        with self._apply_patches(patches):
            analyzer = self._setup_analyzer(config, "ip", "2001:4860:4860::8888")
            report = analyzer.run()
        self.assertEqual(report["ip"], "2001:4860:4860::8888")
        self.assertEqual(report["country_short"], "US")
        self.assertEqual(report["asn"], 15169)

    def test_download_uses_documented_url_and_extracts_bin(self):
        calls = []

        def fake_get(url, params=None, timeout=None, allow_redirects=None):
            calls.append(
                {
                    "url": url,
                    "params": params,
                    "timeout": timeout,
                    "allow_redirects": allow_redirects,
                }
            )
            return _BinaryResponse(_zip_bytes(payload=b"BINDATA"))

        destination = self._destination("IP2LOCATION-LITE-DB11.IPV6.BIN")
        with patch(
            "api_app.analyzers_manager.observable_analyzers.ip2location_lite.requests.get",
            side_effect=fake_get,
        ):
            IP2LocationLITE._download_database(DB11_LITE_IPV6_CODE, "secret-token", destination)
        self.assertEqual(calls[0]["url"], DOWNLOAD_URL)
        self.assertEqual(calls[0]["params"]["file"], DB11_LITE_IPV6_CODE)
        self.assertEqual(calls[0]["params"]["token"], "secret-token")
        self.assertTrue(calls[0]["allow_redirects"])
        with open(destination, "rb") as handle:
            self.assertEqual(handle.read(), b"BINDATA")
        os.remove(destination)

    def test_asn_download_code_is_sent(self):
        seen = {}

        def fake_get(url, params=None, timeout=None, allow_redirects=None):
            seen["params"] = params
            return _BinaryResponse(_zip_bytes("IP2LOCATION-LITE-ASN.IPV6.BIN", b"ASN"))

        destination = self._destination("IP2LOCATION-LITE-ASN.IPV6.BIN")
        with patch(
            "api_app.analyzers_manager.observable_analyzers.ip2location_lite.requests.get",
            side_effect=fake_get,
        ):
            IP2LocationLITE._download_database(ASN_LITE_IPV6_CODE, "secret-token", destination)
        self.assertEqual(seen["params"]["file"], ASN_LITE_IPV6_CODE)
        os.remove(destination)

    def test_download_rejects_non_zip_body(self):
        destination = self._destination("rejected.bin")
        with (
            patch(
                "api_app.analyzers_manager.observable_analyzers.ip2location_lite.requests.get",
                return_value=_BinaryResponse(b"INVALID TOKEN"),
            ),
            self.assertRaises(AnalyzerRunException) as caught,
        ):
            IP2LocationLITE._download_database(DB11_LITE_IPV6_CODE, "secret-token", destination)
        self.assertNotIn("secret-token", str(caught.exception))
        self.assertFalse(os.path.exists(destination))

    @staticmethod
    def _destination(filename):
        directory = os.path.join("/tmp", "ip2location-lite-tests")
        os.makedirs(directory, exist_ok=True)
        return os.path.join(directory, filename)
