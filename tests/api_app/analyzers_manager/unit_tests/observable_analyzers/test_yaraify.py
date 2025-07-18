from unittest.mock import patch

from api_app.analyzers_manager.observable_analyzers.yaraify import YARAify
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)
from tests.mock_utils import MockUpResponse


class YARAifyTestCase(BaseAnalyzerTest):
    analyzer_class = YARAify

    @staticmethod
    def get_mocked_response():
        mock_response = {
            "query_status": "ok",
            "data": [
                {
                    "sha256_hash": "deadbeef1234567890",
                    "yara_rule": "Suspicious_Pattern",
                    "description": "Matched suspicious rule",
                }
            ],
        }
        return patch("requests.post", return_value=MockUpResponse(mock_response, 200))

    @classmethod
    def get_extra_config(cls) -> dict:
        return {
            "query": "search_sample",
            "result_max": 1,
            "_api_key_name": "test_yaraify_token",
        }
