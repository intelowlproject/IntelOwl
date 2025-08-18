from unittest.mock import patch

from api_app.analyzers_manager.observable_analyzers.ha_get import HybridAnalysisGet
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)
from tests.mock_utils import MockUpResponse


class HybridAnalysisGetTestCase(BaseAnalyzerTest):
    analyzer_class = HybridAnalysisGet

    @staticmethod
    def get_mocked_response():
        mock_response = [
            {
                "sha256": "abcd1234efgh5678ijkl9012mnop3456qrst7890uvwx1234yzab5678cdef9012",
                "job_id": "12345",
                "threat_score": 85,
                "verdict": "malicious",
            }
        ]
        return patch(
            "requests.post",
            return_value=MockUpResponse(mock_response, 200),
        )

    @classmethod
    def get_extra_config(cls) -> dict:
        return {
            "_api_key_name": "test_api_key",
        }
