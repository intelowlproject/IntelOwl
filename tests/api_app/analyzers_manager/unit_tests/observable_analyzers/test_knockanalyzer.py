from unittest.mock import patch

from api_app.analyzers_manager.observable_analyzers.knockanalyzer import KnockAnalyzer
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)


class KnockAnalyzerTestCase(BaseAnalyzerTest):
    analyzer_class = KnockAnalyzer

    @staticmethod
    def get_mocked_response():
        mock_response = {
            "subdomains": ["dev.example.com", "api.example.com"],
            "status": "success",
        }

        return patch("knock.knockpy.KNOCKPY", return_value=mock_response)

    @classmethod
    def get_extra_config(cls) -> dict:
        return {
            "dns": "8.8.8.8",
            "useragent": "Mozilla/5.0",
            "timeout": 10,
            "threads": 4,
            "recon": True,
            "bruteforce": True,
        }
