from unittest.mock import MagicMock, patch

from django.test import TestCase

from IntelOwl.api_app.analyzers_manager.observable_analyzers.clean_browsing import (
    CleanBrowsing,
)


class CleanBrowsingTest(TestCase):

    def setUp(self):
        self.observable_name = "google.com"
        # This binary simulates a "Blocked" response (RCODE 3)
        self.blocked_content = b"\x00\x00\x81\x83\x00\x01\x00\x00\x00\x00\x00\x00"

    @patch("api_app.analyzers_manager.observable_analyzers.CleanBrowsing.requests.get")
    def test_routing_security(self, mock_get):
        """Test that selecting 'security' hits the correct Security URL"""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = self.blocked_content
        mock_get.return_value = mock_response

        analyzer = CleanBrowsing(MagicMock())
        analyzer.observable_name = self.observable_name
        analyzer.filter_type = "security"

        analyzer.run()

        # Check URL
        args, _ = mock_get.call_args
        called_url = args[0]
        self.assertEqual(called_url, CleanBrowsing.URL_SECURITY)

    @patch("api_app.analyzers_manager.observable_analyzers.CleanBrowsing.requests.get")
    def test_routing_adult(self, mock_get):
        """Test that selecting 'adult' hits the correct Adult URL"""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = self.blocked_content
        mock_get.return_value = mock_response

        analyzer = CleanBrowsing(MagicMock())
        analyzer.observable_name = self.observable_name
        analyzer.filter_type = "adult"

        analyzer.run()

        args, _ = mock_get.call_args
        self.assertEqual(args[0], CleanBrowsing.URL_ADULT)

    @patch("api_app.analyzers_manager.observable_analyzers.CleanBrowsing.requests.get")
    def test_default_family(self, mock_get):
        """Test that default hits the Family URL"""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = self.blocked_content
        mock_get.return_value = mock_response

        analyzer = CleanBrowsing(MagicMock())
        analyzer.observable_name = self.observable_name
        # We don't set filter_type here to test defaults

        analyzer.run()

        args, _ = mock_get.call_args
        self.assertEqual(args[0], CleanBrowsing.URL_FAMILY)
