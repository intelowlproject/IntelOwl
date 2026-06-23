# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from unittest.mock import MagicMock, patch

from api_app.analyzers_manager.exceptions import AnalyzerRunException
from api_app.analyzers_manager.observable_analyzers.rdap import Rdap
from api_app.choices import Classification
from tests import CustomTestCase


class RdapTestCase(CustomTestCase):
    """Unit tests for the RDAP analyzer (mocked HTTP, no live calls)."""

    @staticmethod
    def _analyzer(observable_name, classification):
        analyzer = Rdap(config={})
        analyzer.observable_name = observable_name
        analyzer.observable_classification = classification
        return analyzer

    @staticmethod
    def _ok(json_data):
        response = MagicMock(status_code=200)
        response.raise_for_status.return_value = None
        response.json.return_value = json_data
        return response

    @patch("api_app.analyzers_manager.observable_analyzers.rdap.requests.get")
    def test_domain_found(self, mock_get):
        mock_get.return_value = self._ok({"objectClassName": "domain", "ldhName": "example.com"})
        result = self._analyzer("example.com", Classification.DOMAIN).run()
        self.assertTrue(result["found"])
        self.assertEqual(result["ldhName"], "example.com")
        self.assertIn("rdap.org/domain/example.com", mock_get.call_args.args[0])

    @patch("api_app.analyzers_manager.observable_analyzers.rdap.requests.get")
    def test_ip_uses_ip_endpoint(self, mock_get):
        mock_get.return_value = self._ok({"objectClassName": "ip network"})
        self._analyzer("1.1.1.1", Classification.IP).run()
        self.assertIn("rdap.org/ip/1.1.1.1", mock_get.call_args.args[0])

    @patch("api_app.analyzers_manager.observable_analyzers.rdap.requests.get")
    def test_url_resolves_to_host_domain(self, mock_get):
        mock_get.return_value = self._ok({"objectClassName": "domain"})
        self._analyzer("https://sub.example.com/path?q=1", Classification.URL).run()
        self.assertIn("rdap.org/domain/sub.example.com", mock_get.call_args.args[0])

    @patch("api_app.analyzers_manager.observable_analyzers.rdap.requests.get")
    def test_url_with_ip_host_uses_ip_endpoint(self, mock_get):
        mock_get.return_value = self._ok({"objectClassName": "ip network"})
        self._analyzer("http://1.1.1.1/path", Classification.URL).run()
        self.assertIn("rdap.org/ip/1.1.1.1", mock_get.call_args.args[0])

    @patch("api_app.analyzers_manager.observable_analyzers.rdap.requests.get")
    def test_non_json_response_raises(self, mock_get):
        response = MagicMock(status_code=200)
        response.raise_for_status.return_value = None
        response.json.side_effect = ValueError("Expecting value")
        mock_get.return_value = response
        with self.assertRaises(AnalyzerRunException):
            self._analyzer("example.com", Classification.DOMAIN).run()

    @patch("api_app.analyzers_manager.observable_analyzers.rdap.requests.get")
    def test_not_found_returns_clean_negative(self, mock_get):
        mock_get.return_value = MagicMock(status_code=404)
        result = self._analyzer("does-not-exist.invalid", Classification.DOMAIN).run()
        self.assertEqual(result, {"found": False})

    def test_unsupported_classification_raises(self):
        with self.assertRaises(AnalyzerRunException):
            self._analyzer("deadbeefdeadbeef", Classification.HASH).run()

    def test_url_without_hostname_raises(self):
        with self.assertRaises(AnalyzerRunException):
            self._analyzer("not-a-url", Classification.URL).run()
