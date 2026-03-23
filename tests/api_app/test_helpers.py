# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.test import TestCase

from api_app.choices import Classification
from api_app.helpers import mask_recursive, mask_sensitive_data


class HelperTests(TestCase):
    def test_accept_defanged_domains(self):
        observable = "www\.test\.com"
        result = Classification.calculate_observable(observable)
        self.assertEqual(result, Classification.DOMAIN)

        observable = "www[.]test[.]com"
        result = Classification.calculate_observable(observable)
        self.assertEqual(result, Classification.DOMAIN)

    def test_calculate_observable_classification(self):
        observable = "7.7.7.7"
        result = Classification.calculate_observable(observable)
        self.assertEqual(result, Classification.IP)

        observable = "www.test.com"
        result = Classification.calculate_observable(observable)
        self.assertEqual(result, Classification.DOMAIN)

        observable = ".www.test.com"
        result = Classification.calculate_observable(observable)
        self.assertEqual(result, Classification.DOMAIN)

        observable = "ftp://www.test.com"
        result = Classification.calculate_observable(observable)
        self.assertEqual(result, Classification.URL)

        observable = "b318ff1839771c22e50d316af613dc70"
        result = Classification.calculate_observable(observable)
        self.assertEqual(result, Classification.HASH)

        observable = "iammeia"
        result = Classification.calculate_observable(observable)
        self.assertEqual(result, Classification.GENERIC)

    def test_mask_sensitive_data(self):
        self.assertEqual(mask_sensitive_data("secret123", True), "<redacted>")
        self.assertEqual(mask_sensitive_data("public123", False), "public123")

    def test_mask_recursive_dict(self):
        data = {
            "api_key": "secret_key",
            "username": "user1",
            "password": "secret_password",
            "nested": {"token": "secret_token", "normal": "value"},
        }
        expected = {
            "api_key": "<redacted>",
            "username": "user1",
            "password": "<redacted>",
            "nested": {"token": "<redacted>", "normal": "value"},
        }
        self.assertEqual(mask_recursive(data), expected)

    def test_mask_recursive_substring(self):
        data = {
            "_api_key": "secret",
            "password_field": "secret",
            "auth_token": "secret",
            "apiKey": "secret",  # camelCase support
            "myPassword": "secret",  # camelCase support
            "authToken": "secret",  # camelCase support
            "secretValue": "secret",  # camelCase support
            "monkey": "is_safe",  # Still safe
            "normal_field": "safe",
        }
        expected = {
            "_api_key": "<redacted>",
            "password_field": "<redacted>",
            "auth_token": "<redacted>",
            "apiKey": "<redacted>",
            "myPassword": "<redacted>",
            "authToken": "<redacted>",
            "secretValue": "<redacted>",
            "monkey": "is_safe",
            "normal_field": "safe",
        }
        self.assertEqual(mask_recursive(data), expected)

    def test_mask_recursive_list(self):
        data = [{"key": "secret"}, {"other": "safe"}]
        expected = [{"key": "<redacted>"}, {"other": "safe"}]
        self.assertEqual(mask_recursive(data), expected)

    def test_mask_recursive_case_insensitive(self):
        data = {"API_KEY": "secret", "Password": "secret"}
        expected = {"API_KEY": "<redacted>", "Password": "<redacted>"}
        self.assertEqual(mask_recursive(data), expected)
