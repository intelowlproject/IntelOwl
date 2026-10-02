# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from unittest.mock import MagicMock, patch

from api_app.analyzers_manager.observable_analyzers.phishunt import Phishunt
from api_app.choices import Classification
from tests import CustomTestCase


class PhishuntTestCase(CustomTestCase):
    """Unit tests for the Phishunt analyzer (mocked HTTP, no live calls)."""

    @staticmethod
    def _analyzer(observable_name, classification):
        analyzer = Phishunt(config={})
        analyzer.observable_name = observable_name
        analyzer.observable_classification = classification
        return analyzer

    @staticmethod
    def _ok(json_data):
        response = MagicMock(status_code=200)
        response.raise_for_status.return_value = None
        response.json.return_value = json_data
        return response

    @patch("api_app.analyzers_manager.observable_analyzers.phishunt.requests.get")
    def test_domain_returns_exact_match(self, mock_get):
        mock_get.return_value = self._ok(
            {
                "query": "example.com",
                "count": 2,
                "results": [
                    {
                        "domain": "example.com",
                        "url": "https://example.com/login",
                        "company": "Example",
                        "first_seen": "2026-01-01",
                        "ip": "1.2.3.4",
                        "asn": "AS12345",
                        "org": "Example Org",
                        "cert": "Example CA",
                    },
                    {
                        "domain": "notexample.com",
                        "url": "https://notexample.com",
                    },
                ],
            }
        )

        result = self._analyzer(
            "example.com",
            Classification.DOMAIN,
        ).run()

        self.assertTrue(result["found"])
        self.assertEqual(len(result["results"]), 1)
        self.assertEqual(result["results"][0]["domain"], "example.com")
        mock_get.assert_called_once_with(
            Phishunt.url,
            params={"q": "example.com"},
            timeout=30,
        )

    @patch("api_app.analyzers_manager.observable_analyzers.phishunt.requests.get")
    def test_url_uses_hostname_and_exact_match(self, mock_get):
        mock_get.return_value = self._ok(
            {
                "query": "example.com",
                "count": 1,
                "results": [
                    {
                        "domain": "example.com",
                        "url": "https://example.com/login",
                    }
                ],
            }
        )

        result = self._analyzer(
            "https://example.com/login",
            Classification.URL,
        ).run()

        self.assertTrue(result["found"])
        self.assertEqual(result["results"][0]["domain"], "example.com")
        mock_get.assert_called_once_with(
            Phishunt.url,
            params={"q": "example.com"},
            timeout=30,
        )

    @patch("api_app.analyzers_manager.observable_analyzers.phishunt.requests.get")
    def test_ip_returns_exact_match(self, mock_get):
        mock_get.return_value = self._ok(
            {
                "query": "1.2.3.4",
                "count": 2,
                "results": [
                    {
                        "domain": "example.com",
                        "ip": "1.2.3.4",
                    },
                    {
                        "domain": "other.com",
                        "ip": "5.6.7.8",
                    },
                ],
            }
        )

        result = self._analyzer(
            "1.2.3.4",
            Classification.IP,
        ).run()

        self.assertTrue(result["found"])
        self.assertEqual(len(result["results"]), 1)
        self.assertEqual(result["results"][0]["ip"], "1.2.3.4")

    @patch("api_app.analyzers_manager.observable_analyzers.phishunt.requests.get")
    def test_substring_match_is_ignored(self, mock_get):
        mock_get.return_value = self._ok(
            {
                "query": "example.com",
                "count": 1,
                "results": [
                    {
                        "domain": "notexample.com",
                        "url": "https://notexample.com/login",
                    }
                ],
            }
        )

        result = self._analyzer(
            "example.com",
            Classification.DOMAIN,
        ).run()

        self.assertFalse(result["found"])
        self.assertEqual(result["results"], [])
