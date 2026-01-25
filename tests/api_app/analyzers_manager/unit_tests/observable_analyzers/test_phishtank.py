from unittest.mock import patch

from api_app.analyzers_manager.observable_analyzers.phishtank import Phishtank
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)
from tests.mock_utils import MockUpResponse


class PhishtankTestCase(BaseAnalyzerTest):
    analyzer_class = Phishtank

    @staticmethod
    def get_mocked_response():
        mock_json_response = {
            "meta": {
                "timestamp": "2025-07-15 12:00:00",
            },
            "results": {
                "url": "http://example.com/",
                "in_database": True,
                "phish_id": "1234567",
                "verified": True,
                "valid": True,
            },
        }

        return patch(
            "requests.post",
            return_value=MockUpResponse(mock_json_response, 200),
        )

    @classmethod
    def get_extra_config(cls) -> dict:
        return {"_api_key_name": "mocked-key"}
