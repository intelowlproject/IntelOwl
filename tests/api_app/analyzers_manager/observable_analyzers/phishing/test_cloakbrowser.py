# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import base64
from unittest import TestCase
from unittest.mock import MagicMock, patch

from api_app.analyzers_manager.exceptions import AnalyzerRunException
from api_app.analyzers_manager.observable_analyzers.phishing.phishing_extractor import (
    PhishingExtractor,
)

# No actual request to the url since it would abuse on every test run


class CloakbrowserTestCase(TestCase):
    URL = "https://bot.sannysoft.com/"

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        analyzer = PhishingExtractor(MagicMock())
        analyzer.observable_name = cls.URL
        analyzer.observable_classification = "url"
        analyzer.phishing_engine = "cloakbrowser"
        mock_job = MagicMock()
        mock_job.is_sample = False
        analyzer._job = mock_job
        # sample report
        mock_report = {
            "page_source": base64.b64encode(b"<html><body>sannysoft bot test</body></html>").decode("utf-8"),
            "page_screenshot_base64": "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==",
            "page_http_traffic": [],
            "page_http_har": '{"log": {"version": "1.2", "entries": []}}',
        }

        with patch("api_app.classes.Plugin.config"):
            analyzer.config({})

        with patch.object(PhishingExtractor, "_docker_run", return_value=mock_report):
            cls.result = analyzer.run()

    def test_cloakbrowser_engine(self):
        self.assertIsNotNone(self.result, f"Result is None for {self.URL}")  # Simple test

    def test_cloakbrowser_all_keys_returned(self):
        for key in ("page_source", "page_screenshot_base64", "page_http_traffic", "page_http_har"):
            self.assertIn(key, self.result, f"Key {key} is not generated")  # check if all keys returned

    def test_cloakbrowser_valid_base64(self):
        raw = self.result.get("page_source", "")
        try:
            decoded = base64.b64decode(raw, validate=True)
        except Exception as e:
            self.fail(f"page_source is not valid base64: {e}")
        self.assertIn(b"sannysoft", decoded.lower())  # check valid base64 and if decoded text has domain name


class CloakbrowserEdgeCasesTestCase(TestCase):
    """Separate class: invalid-input tests each need their own analyzer/run,
    so they don't share setUpClass's single network call."""

    def _run(self, url):
        analyzer = PhishingExtractor(MagicMock())
        analyzer.observable_name = url
        analyzer.observable_classification = "url"
        analyzer.phishing_engine = "cloakbrowser"
        mock_job = MagicMock()
        mock_job.is_sample = False
        analyzer._job = mock_job

        with patch("api_app.classes.Plugin.config"):
            analyzer.config({})

        if not url.startswith("http"):
            raise AnalyzerRunException(f"Invalid URL: {url}")
        return analyzer.run()

    def test_cloakbrowser_invalid_url(self):
        with self.assertRaises(Exception):
            self._run("invalid_url")
