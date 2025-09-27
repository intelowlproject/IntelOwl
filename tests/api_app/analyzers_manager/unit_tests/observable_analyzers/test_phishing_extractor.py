from unittest.mock import patch

from api_app.analyzers_manager.observable_analyzers.phishing.phishing_extractor import (
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
