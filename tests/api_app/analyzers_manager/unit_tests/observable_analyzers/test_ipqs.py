from unittest.mock import patch

from api_app.analyzers_manager.observable_analyzers.ipqs import IPQualityScore
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)
from tests.mock_utils import MockUpResponse


class IPQualityScoreTestCase(BaseAnalyzerTest):
    analyzer_class = IPQualityScore

    @staticmethod
    def get_mocked_response():
        mock_response = {
            "message": "Success.",
            "success": True,
            "unsafe": False,
            "domain": "test.com",
            "risk_score": 0,
        }
        return patch("requests.get", return_value=MockUpResponse(mock_response, 200))

    @classmethod
    def get_extra_config(cls) -> dict:
        return {"_ipqs_api_key": "dummy_key"}
