from django.test import TestCase
from api_app.helpers import mask_recursive, mask_sensitive_data

class SecretLeakageTests(TestCase):
    def test_mask_sensitive_data(self):
        self.assertEqual(mask_sensitive_data("secret123", True), "<redacted>")
        self.assertEqual(mask_sensitive_data("public123", False), "public123")

    def test_mask_recursive_dict(self):
        data = {
            "api_key": "secret_key",
            "username": "user1",
            "password": "secret_password",
            "nested": {
                "token": "secret_token",
                "normal": "value"
            }
        }
        expected = {
            "api_key": "<redacted>",
            "username": "user1",
            "password": "<redacted>",
            "nested": {
                "token": "<redacted>",
                "normal": "value"
            }
        }
        self.assertEqual(mask_recursive(data), expected)

    def test_mask_recursive_substring(self):
        data = {
            "_api_key": "secret",
            "my_password_field": "secret",
            "authentication_token": "secret",
            "normal_field": "safe"
        }
        expected = {
            "_api_key": "<redacted>",
            "my_password_field": "<redacted>",
            "authentication_token": "<redacted>",
            "normal_field": "safe"
        }
        self.assertEqual(mask_recursive(data), expected)

    def test_mask_recursive_list(self):
        data = [
            {"key": "secret"},
            {"other": "safe"}
        ]
        expected = [
            {"key": "<redacted>"},
            {"other": "safe"}
        ]
        self.assertEqual(mask_recursive(data), expected)

    def test_mask_recursive_case_insensitive(self):
        data = {
            "API_KEY": "secret",
            "Password": "secret"
        }
        expected = {
            "API_KEY": "<redacted>",
            "Password": "<redacted>"
        }
        self.assertEqual(mask_recursive(data), expected)
