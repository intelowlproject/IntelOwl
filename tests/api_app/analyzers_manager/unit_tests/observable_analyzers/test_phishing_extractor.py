from unittest.mock import MagicMock, patch

from api_app.analyzers_manager.observable_analyzers.phishing.phishing_extractor import (
    _ENGINE_ENDPOINTS,
    PhishingExtractor,
)
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)


class PhishingExtractorTestCase(BaseAnalyzerTest):
    analyzer_class = PhishingExtractor

    @classmethod
    def get_extra_config(cls):
        return {
            "window_width": 1920,
            "window_height": 1080,
            "proxy_address": "http://localhost:8080",
            "user_agent": "Mozilla/5.0 (TestAgent)",
        }

    @staticmethod
    def get_mocked_response():
        mocked_response = {
            "stdout": "Fake extraction result",
            "stderr": "",
            "exit_code": 0,
        }
        return [
            patch(
                "api_app.analyzers_manager.observable_analyzers.phishing.phishing_extractor.PhishingExtractor._docker_run",
                return_value=mocked_response,
            )
        ]

    def _make_analyzer(self, phishing_engine=None):
        analyzer = PhishingExtractor(MagicMock())
        analyzer.observable_name = "https://example.com"
        analyzer.observable_classification = "url"
        analyzer._job = self._create_mock_analyzer_job("https://example.com", "url")
        if phishing_engine is not None:
            analyzer.phishing_engine = phishing_engine
        return analyzer

    def _config_analyzer(self, analyzer):
        with patch("api_app.classes.Plugin.config"):
            analyzer.config({})

    def test_default_engine_is_selenium(self):
        analyzer = self._make_analyzer()
        self.assertEqual(analyzer.phishing_engine, "selenium")
        self.assertEqual(analyzer.url, _ENGINE_ENDPOINTS["selenium"])

    def test_selenium_engine_sets_selenium_url(self):
        analyzer = self._make_analyzer(phishing_engine="selenium")
        self._config_analyzer(analyzer)
        self.assertEqual(analyzer.url, _ENGINE_ENDPOINTS["selenium"])

    def test_playwright_engine_sets_playwright_url(self):
        analyzer = self._make_analyzer(phishing_engine="playwright")
        self._config_analyzer(analyzer)
        self.assertEqual(analyzer.url, _ENGINE_ENDPOINTS["playwright"])

    def test_invalid_engine_falls_back_to_selenium(self):
        analyzer = self._make_analyzer(phishing_engine="unknown_engine")
        self._config_analyzer(analyzer)
        self.assertEqual(analyzer.url, _ENGINE_ENDPOINTS["selenium"])

    def test_engine_value_is_case_insensitive(self):
        analyzer = self._make_analyzer(phishing_engine="Playwright")
        self._config_analyzer(analyzer)
        self.assertEqual(analyzer.url, _ENGINE_ENDPOINTS["playwright"])

    def test_domain_target_prefixed_with_http(self):
        analyzer = self._make_analyzer()
        analyzer.observable_name = "evil.example.com"
        analyzer.observable_classification = "domain"
        self._config_analyzer(analyzer)
        self.assertIn("--target=http://evil.example.com", analyzer.args)

    def test_url_target_not_modified(self):
        analyzer = self._make_analyzer()
        analyzer.observable_name = "https://evil.example.com/login"
        analyzer.observable_classification = "url"
        self._config_analyzer(analyzer)
        self.assertIn("--target=https://evil.example.com/login", analyzer.args)
