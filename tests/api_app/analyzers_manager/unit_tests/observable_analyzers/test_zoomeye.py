from unittest.mock import patch

from api_app.analyzers_manager.observable_analyzers.zoomeye import ZoomEye
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)
from tests.mock_utils import MockUpResponse


class ZoomEyeTestCase(BaseAnalyzerTest):
    analyzer_class = ZoomEye

    @staticmethod
    def get_mocked_response():
        mock_response = {
            "matches": [{"ip": "8.8.8.8", "portinfo": {"port": 80, "service": "http"}}],
            "total": 1,
        }
        return patch("requests.get", return_value=MockUpResponse(mock_response, 200))

    @classmethod
    def get_extra_config(cls) -> dict:
        return {
            "search_type": "host",
            "query": "",
            "page": 1,
            "facets": ["app", "os"],
            "history": False,
            "_api_key_name": "test_token",
        }
