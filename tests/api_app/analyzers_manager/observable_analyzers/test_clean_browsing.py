from unittest.mock import MagicMock, patch

from django.test import TestCase
from requests.exceptions import RequestException

from api_app.analyzers_manager.exceptions import AnalyzerRunException
from api_app.analyzers_manager.observable_analyzers.clean_browsing import CleanBrowsing
from tests.mock_utils import MockUpResponse, if_mock_connections


@if_mock_connections
class CleanBrowsingTest(TestCase):
    def setUp(self):
        self.observable_name = "google.com"
        # RCODE 3 (Blocked)
        self.blocked_content = b"\x00\x00\x81\x83\x00\x01\x00\x00\x00\x00\x00\x00"
        # RCODE 0 (Allowed)
        self.allowed_content = b"\x00\x00\x81\x80\x00\x01\x00\x00\x00\x00\x00\x00"

    @patch("api_app.analyzers_manager.observable_analyzers.clean_browsing.requests.get")
    def test_routing_security_blocked(self, mock_get):
        """Test 'security' filter routing and blocked response"""
        # FIXED: Added json_data=None
        mock_get.return_value = MockUpResponse(
            json_data=None, status_code=200, content=self.blocked_content
        )

        analyzer = CleanBrowsing(MagicMock())
        analyzer.observable_name = self.observable_name
        analyzer.configuration = {"filter_type": "security"}

        result = analyzer.run()

        args, _ = mock_get.call_args
        self.assertIn("security-filter", args[0])
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["filter_used"], "security")

    @patch("api_app.analyzers_manager.observable_analyzers.clean_browsing.requests.get")
    def test_routing_adult_allowed(self, mock_get):
        """Test 'adult' filter routing and allowed response"""
        # FIXED: Added json_data=None
        mock_get.return_value = MockUpResponse(
            json_data=None, status_code=200, content=self.allowed_content
        )

        analyzer = CleanBrowsing(MagicMock())
        analyzer.observable_name = self.observable_name
        analyzer.configuration = {"filter_type": "adult"}

        result = analyzer.run()

        args, _ = mock_get.call_args
        self.assertIn("adult-filter", args[0])
        self.assertEqual(result["status"], "allowed")
        self.assertEqual(result["filter_used"], "adult")

    @patch("api_app.analyzers_manager.observable_analyzers.clean_browsing.requests.get")
    def test_default_family(self, mock_get):
        """Test default filter (family)"""
        # FIXED: Added json_data=None
        mock_get.return_value = MockUpResponse(
            json_data=None, status_code=200, content=self.blocked_content
        )

        analyzer = CleanBrowsing(MagicMock())
        analyzer.observable_name = self.observable_name

        analyzer.run()

        args, _ = mock_get.call_args
        self.assertIn("family-filter", args[0])

    @patch("api_app.analyzers_manager.observable_analyzers.clean_browsing.requests.get")
    def test_connection_error(self, mock_get):
        """Test that connection errors raise AnalyzerRunException"""
        mock_get.side_effect = RequestException("Connection timeout")

        analyzer = CleanBrowsing(MagicMock())
        analyzer.observable_name = self.observable_name

        with self.assertRaises(AnalyzerRunException):
            analyzer.run()
