# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from unittest.mock import patch

from django.test import TestCase

from api_app.analyzers_manager.observable_analyzers.hibp_breaches import (
    HibpBreaches,
)
from api_app.analyzers_manager.observable_analyzers.hibp_passwords import (
    HibpPasswords,
)


class HibpPasswordsTestCase(TestCase):
    """Test cases for HibpPasswords analyzer"""

    def setUp(self):
        self.analyzer = HibpPasswords(config={}, job_id=1, additional_config_params={})  # noqa: E501
        # Use "password" as it's a known pwned one
        self.analyzer.observable_name = "password"
        self.analyzer.observable_classification = "generic"

    @patch(
        "api_app.analyzers_manager.observable_analyzers.hibp_passwords.make_hibp_request"  # noqa: E501
    )
    def test_pwned_password_found(self, mock_make_request):
        # SHA-1("password") upper = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
        # prefix = 5BAA6
        # suffix = 1E4C9B93F3F0682250B6CF8331B7EE68FD8
        mock_make_request.return_value = "1E4C9B93F3F0682250B6CF8331B7EE68FD8:42\nOTHER:1\n"

        result = self.analyzer.run()

        self.assertTrue(result["success"])
        self.assertEqual(result["exposure_count"], 42)
        self.assertIn("exposed 42 times", result["summary"])

    @patch(
        "api_app.analyzers_manager.observable_analyzers.hibp_passwords.make_hibp_request"  # noqa: E501
    )
    def test_password_not_found(self, mock_make_request):
        mock_make_request.return_value = "WRONGSUFFIX:5\n"

        self.analyzer.observable_name = "StrongNeverLeakedPass2026!"

        result = self.analyzer.run()

        self.assertTrue(result["success"])
        self.assertEqual(result["exposure_count"], 0)
        self.assertEqual(result["summary"], "Password not found in known breaches.")  # noqa: E501

    def test_unsupported_type(self):
        self.analyzer.observable_classification = "ip"

        with self.assertRaises(RuntimeError) as cm:
            self.analyzer.run()
        self.assertIn("Unsupported observable type", str(cm.exception))


class HibpBreachesTestCase(TestCase):
    """Test cases for HibpBreaches analyzer"""

    def setUp(self):
        self.analyzer = HibpBreaches(config={}, job_id=1, additional_config_params={})  # noqa: E501
        self.analyzer.observable_name = "test@example.com"
        self.analyzer.observable_classification = "generic"
        # Set _api_key_name directly (bypasses config lookup)
        self.analyzer._api_key_name = "00000000000000000000000000000000"

    @patch(
        "api_app.analyzers_manager.observable_analyzers.hibp_breaches.make_hibp_request"  # noqa: E501
    )
    def test_email_found(self, mock_make_request):
        mock_make_request.return_value = [{"Name": "TestBreach", "PwnCount": 100}]  # noqa: E501

        result = self.analyzer.run()
        self.assertTrue(result["success"])
        self.assertEqual(result["breach_count"], 1)

    @patch(
        "api_app.analyzers_manager.observable_analyzers.hibp_breaches.make_hibp_request"  # noqa: E501
    )
    def test_domain_no_breaches(self, mock_make_request):
        mock_make_request.return_value = []

        self.analyzer.observable_name = "example.com"
        self.analyzer.observable_classification = "domain"

        result = self.analyzer.run()
        self.assertTrue(result["success"])
        self.assertEqual(result["breach_count"], 0)
        self.assertIn("note", result)

    def test_invalid_input(self):
        self.analyzer.observable_name = "8.8.8.8"
        self.analyzer.observable_classification = "generic"

        with self.assertRaises(RuntimeError):
            self.analyzer.run()

    def test_no_api_key(self):
        self.analyzer._api_key_name = ""

        with self.assertRaises(RuntimeError):
            self.analyzer.run()
