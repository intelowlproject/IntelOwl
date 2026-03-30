from unittest.mock import patch

import requests

from api_app.analyzers_manager.models import Ja4DBEntry
from api_app.analyzers_manager.observable_analyzers.ja4_db import Ja4DB
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)
from tests.mock_utils import MockUpResponse


class Ja4DBTestCase(BaseAnalyzerTest):
    analyzer_class = Ja4DB

    @staticmethod
    def get_mocked_response():
        sample_data = [
            {
                "application": "Nmap",
                "library": None,
                "device": None,
                "os": None,
                "user_agent_string": None,
                "certificate_authority": None,
                "observation_count": 1,
                "verified": True,
                "notes": "",
                "ja4_fingerprint": None,
                "ja4_fingerprint_string": None,
                "ja4s_fingerprint": None,
                "ja4h_fingerprint": None,
                "ja4x_fingerprint": None,
                "ja4t_fingerprint": "1024_2_1460_00",
                "ja4ts_fingerprint": None,
                "ja4tscan_fingerprint": None,
            },
            {
                "application": "Chrome",
                "library": None,
                "device": None,
                "os": "Windows",
                "user_agent_string": "Mozilla/5.0...",
                "certificate_authority": None,
                "observation_count": 1,
                "verified": False,
                "notes": None,
                "ja4_fingerprint": "t13d1517h2_8daaf6152771_b0da82dd1658",
                "ja4_fingerprint_string": "t13d1517h2_...",
                "ja4s_fingerprint": None,
                "ja4h_fingerprint": "ge11cn20enus_60ca1bd65281_ac95b44401d9_8df6a44f726c",
                "ja4x_fingerprint": None,
                "ja4t_fingerprint": None,
                "ja4ts_fingerprint": None,
                "ja4tscan_fingerprint": None,
            },
        ]
        return patch("requests.get", return_value=MockUpResponse(sample_data, 200))

    def test_run_matches_ja4h_fingerprint(self):
        Ja4DBEntry.objects.create(
            fingerprint_type="ja4h_fingerprint",
            fingerprint_value="ge11cn20enus_60ca1bd65281_ac95b44401d9_8df6a44f726c",
            details={
                "application": "Chrome",
                "ja4h_fingerprint": "ge11cn20enus_60ca1bd65281_ac95b44401d9_8df6a44f726c",
            },
        )

        analyzer = self._setup_analyzer(
            None,
            "generic",
            "ge11cn20enus_60ca1bd65281_ac95b44401d9_8df6a44f726c",
        )

        response = analyzer.run()

        self.assertTrue(response["found"])
        self.assertIn(
            "Chrome",
            {item["application"] for item in response["results"]},
        )

    def test_run_matches_ja4t_fingerprint(self):
        Ja4DBEntry.objects.create(
            fingerprint_type="ja4t_fingerprint",
            fingerprint_value="1024_2_1460_00",
            details={"application": "Nmap", "ja4t_fingerprint": "1024_2_1460_00"},
        )

        analyzer = self._setup_analyzer(None, "generic", "1024_2_1460_00")

        response = analyzer.run()

        self.assertTrue(response["found"])
        self.assertIn(
            "Nmap",
            {item["application"] for item in response["results"]},
        )

    def test_run_matches_ja4x_fingerprint(self):
        Ja4DBEntry.objects.create(
            fingerprint_type="ja4x_fingerprint",
            fingerprint_value="3082024b308201b3a00302010202143d0f5c",
            details={
                "application": "Example TLS Cert",
                "ja4x_fingerprint": "3082024b308201b3a00302010202143d0f5c",
            },
        )

        analyzer = self._setup_analyzer(None, "generic", "3082024b308201b3a00302010202143d0f5c")

        response = analyzer.run()

        self.assertTrue(response["found"])
        self.assertIn(
            "Example TLS Cert",
            {item["application"] for item in response["results"]},
        )

    def test_run_returns_all_matching_records(self):
        fingerprint_value = "shared-fingerprint"
        Ja4DBEntry.objects.create(
            fingerprint_type="ja4h_fingerprint",
            fingerprint_value=fingerprint_value,
            details={"application": "Chrome", "ja4h_fingerprint": fingerprint_value},
        )
        Ja4DBEntry.objects.create(
            fingerprint_type="ja4tscan_fingerprint",
            fingerprint_value=fingerprint_value,
            details={"application": "Scanner", "ja4tscan_fingerprint": fingerprint_value},
        )

        analyzer = self._setup_analyzer(None, "generic", fingerprint_value)

        response = analyzer.run()

        self.assertTrue(response["found"])
        self.assertEqual(len(response["results"]), 2)
        self.assertEqual(
            {item["application"] for item in response["results"]},
            {"Chrome", "Scanner"},
        )

    def test_run_returns_error_when_initial_update_fails(self):
        analyzer = self._setup_analyzer(None, "generic", "missing-fingerprint")
        Ja4DBEntry.objects.all().delete()

        with patch.object(Ja4DB, "update", side_effect=requests.RequestException("network down")):
            response = analyzer.run()

        self.assertEqual(response, {"error": "Unable to update JA4 DB: network down"})
