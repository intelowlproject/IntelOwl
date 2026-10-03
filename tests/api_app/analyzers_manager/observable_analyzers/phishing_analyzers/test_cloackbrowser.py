# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
import base64
from unittest import TestCase

from api_app.analyzers_manager.observable_analyzers.phishing.phishing_extractor import (
    PhishingExtractor,
)


class CloakbrowserTestCase(TestCase):
    URL = "https://bot.sannysoft.com/"

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        analyzer = PhishingExtractor(config={})
        analyzer.observable_name = cls.URL
        analyzer.observable_classification = "url"
        analyzer.phishing_engine = "cloakbrowser"
        analyzer.config({})
        # single call to bot detection website, shared across all tests below
        cls.result = analyzer.run()

    def test_cloakbrowser_engine(self):
        self.assertIsNotNone(self.result, f"Result is None for {self.URL}")  # Basic test

    def test_cloakbrowser_all_keys_returned(self):
        for key in ("page_source", "page_screenshot_base64", "page_http_traffic", "page_http_har"):
            self.assertIn(key, self.result, f"Key {key} is not generated")  # all keys present

    def test_cloakbrowser_valid_base64(self):
        raw = self.result.get("page_source", "")
        try:
            decoded = base64.b64decode(raw, validate=True)
        except Exception as e:
            self.fail(f"page_source is not valid base64: {e}")
        self.assertIn(b"sannysoft", decoded.lower())  # valid base64 & domain name in source


class CloakbrowserEdgeCasesTestCase(TestCase):
    """Separate class: invalid-input tests each need their own analyzer/run,
    so they don't share setUpClass's single network call."""

    def _run(self, url):
        analyzer = PhishingExtractor(config={})
        analyzer.observable_name = url
        analyzer.observable_classification = "url"
        analyzer.phishing_engine = "cloakbrowser"
        analyzer.config({})
        return analyzer.run()

    def test_cloakbrowser_invalid_url(self):
        with self.assertRaises(Exception):
            self._run("invalid_url")
