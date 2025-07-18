from unittest.mock import patch

from api_app.analyzers_manager.observable_analyzers.thug_url import ThugUrl
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)


class ThugUrlTestCase(BaseAnalyzerTest):
    analyzer_class = ThugUrl

    @staticmethod
    def get_mocked_response():
        mock_response = {
            "summary": {
                "network": {"http_requests": 1},
                "javascript": {"functions": ["eval"]},
            },
            "metadata": {"status": "completed"},
        }

        return patch(
            "api_app.analyzers_manager.observable_analyzers.thug_url.ThugUrl._docker_run",
            return_value=mock_response,
        )

    @classmethod
    def get_extra_config(cls) -> dict:
        return {
            "user_agent": "ie",
            "dom_events": "enable",
            "use_proxy": False,
            "proxy": "",
            "enable_awis": True,
            "enable_image_processing_analysis": False,
        }
