import importlib
from unittest.mock import patch

from django.conf import settings
from django.test import SimpleTestCase

from api_app import http_utils


class HttpUtilsTestCase(SimpleTestCase):
    @patch("requests.get")
    def test_get_default_timeout(self, mock_get):
        http_utils.get("http://example.com")
        mock_get.assert_called_with("http://example.com", params=None, timeout=settings.HTTP_TIMEOUT)

    @patch("requests.get")
    def test_get_override_timeout(self, mock_get):
        http_utils.get("http://example.com", timeout=10)
        mock_get.assert_called_with("http://example.com", params=None, timeout=10)

    @patch("requests.post")
    def test_post_override_timeout(self, mock_post):
        http_utils.post("http://example.com", data={"key": "value"}, timeout=10)
        mock_post.assert_called_with("http://example.com", data={"key": "value"}, json=None, timeout=10)

    def test_verify_timeout_decorator(self):
        @http_utils.verify_timeout
        def dummy_request(url, **kwargs):
            """Dummy docstring"""
            return kwargs.get("timeout")

        self.assertEqual(dummy_request("http://example.com"), settings.HTTP_TIMEOUT)
        self.assertEqual(dummy_request("http://example.com", timeout=5), 5)
        # Verify metadata preservation
        self.assertEqual(dummy_request.__name__, "dummy_request")
        self.assertEqual(dummy_request.__doc__, "Dummy docstring")

    def test_config_robustness(self):
        import intel_owl.settings.commons as commons

        test_cases = [
            ("15", 15),
            ("invalid", 90),
            ("0", 90),
            ("-5", 90),
            (" 15 ", 15),
            (None, 90),
        ]

        try:
            for env_value, expected in test_cases:
                with self.subTest(env_value=env_value):

                    def fake_get_secret(key, default=None, env_value=env_value):
                        if key == "HTTP_TIMEOUT":
                            return env_value
                        return default

                    with patch("intel_owl.settings._util.get_secret", side_effect=fake_get_secret):
                        importlib.reload(commons)
                        self.assertEqual(commons.HTTP_TIMEOUT, expected)
        finally:
            importlib.reload(commons)
