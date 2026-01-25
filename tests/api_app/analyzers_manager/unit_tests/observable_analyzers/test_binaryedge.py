from unittest.mock import patch

from api_app.analyzers_manager.observable_analyzers.binaryedge import BinaryEdge
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)
from tests.mock_utils import MockUpResponse


class BinaryEdgeTestCase(BaseAnalyzerTest):
    analyzer_class = BinaryEdge

    @staticmethod
    def get_mocked_response():
        # Simple common response that works for all BinaryEdge endpoints
        mock_response = {
            "events": [
                {
                    "port": 80,
                    "protocol": "tcp",
                    "target": {"ip": "8.8.8.8"},
                    "origin": {"country": "US", "module": "http"},
                }
            ],
            "query": "test_query",
            "total": 1,
        }

        return patch("requests.get", return_value=MockUpResponse(mock_response, 200))

    @classmethod
    def get_extra_config(cls) -> dict:
        return {
            "api_key_name": "test_api_key_123",
            "headers": {"X-Key": "test_api_key_123"},
        }
