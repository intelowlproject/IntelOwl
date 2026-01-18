from unittest.mock import MagicMock, patch

from django.test import TestCase
from requests.exceptions import RequestException

from api_app.analyzers_manager.exceptions import AnalyzerRunException
from api_app.analyzers_manager.observable_analyzers.clean_browsing import CleanBrowsing


class CleanBrowsingTest(TestCase):
    def setUp(self):
        self.observable_name = "google.com"
        # RCODE 3 (Blocked) - 4th byte ends in 3
        self.blocked_content = b"\x00\x00\x81\x83\x00\x01\x00\x00\x00\x00\x00\x00"
        # RCODE 0 (Allowed) - 4th byte ends in 0
        self.allowed_content = b"\x00\x00\x81\x80\x00\x01\x00\x00\x00\x00\x00\x00"

    # NOTE: The patch path is lowercase 'clean_browsing' (the module), NOT 'CleanBrowsing' (the class)
    @patch("api_app.analyzers_manager.observable_analyzers.clean_browsing.requests.get")
    def test_routing_security_blocked(self, mock_get):
        """Test 'security' filter routing and blocked response"""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = self.blocked_content
        mock_get.return_value = mock_response

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
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = self.allowed_content
        mock_get.return_value = mock_response

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
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = self.blocked_content
        mock_get.return_value = mock_response

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
