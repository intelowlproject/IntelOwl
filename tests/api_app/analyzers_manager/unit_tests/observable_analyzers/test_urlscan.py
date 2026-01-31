from unittest.mock import patch

from api_app.analyzers_manager.observable_analyzers.urlscan import UrlScan
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)
from tests.mock_utils import MockUpResponse


class UrlScanTestCase(BaseAnalyzerTest):
    analyzer_class = UrlScan

    @staticmethod
    def get_mocked_response():
        return [
            patch(
                "requests.Session.post",
                return_value=MockUpResponse({"api": "https://urlscan.io/result/abc"}, 200),
            ),
            patch(
                "requests.Session.get",
                return_value=MockUpResponse({"results": [{"task": "completed"}]}, 200),
            ),
        ]

    @classmethod
    def get_extra_config(cls):
        return {
            "urlscan_analysis": "search",  # or "submit_result"
            "visibility": "public",
            "search_size": 10,
            "_api_key_name": "dummy_api_key",
        }
