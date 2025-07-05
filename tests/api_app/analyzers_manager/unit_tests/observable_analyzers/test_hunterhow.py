from unittest.mock import patch

from api_app.analyzers_manager.observable_analyzers.hunter_how import Hunter_How
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)
from tests.mock_utils import MockUpResponse


class HunterHowTestCase(BaseAnalyzerTest):
    analyzer_class = Hunter_How

    @staticmethod
    def get_mocked_response():
        mock_response = {
            "list": [
                {
                    "ip": "8.8.8.8",
                    "domain": "example.com",
                    "timestamp": "2024-01-01T00:00:00Z",
                }
            ]
        }
        return patch("requests.get", return_value=MockUpResponse(mock_response, 200))

    @classmethod
    def get_extra_config(cls) -> dict:
        return {
            "_api_key_name": "dummy_api_key",
            "page": 1,
            "page_size": 20,
            "start_time": "2024-01-01T00:00:00Z",
            "end_time": "2024-12-31T23:59:59Z",
            "parameters": {},
        }
