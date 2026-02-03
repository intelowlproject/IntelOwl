from unittest.mock import patch

from api_app.analyzers_manager.observable_analyzers.securitytrails import SecurityTrails
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)
from tests.mock_utils import MockUpResponse


class SecurityTrailsTestCase(BaseAnalyzerTest):
    analyzer_class = SecurityTrails

    @staticmethod
    def get_mocked_response():
        return patch("requests.get", return_value=MockUpResponse({"test": "value"}, 200))

    @classmethod
    def get_extra_config(cls) -> dict:
        return {
            "_api_key_name": "fake_key",
            "securitytrails_analysis": "current",  # Choose one: "current" or "history"
            "securitytrails_current_type": "subdomains",  # Choose one: "details", "subdomains", "tags"
            "securitytrails_history_analysis": "dns",  # If history, choose: "whois" or "dns"
        }
