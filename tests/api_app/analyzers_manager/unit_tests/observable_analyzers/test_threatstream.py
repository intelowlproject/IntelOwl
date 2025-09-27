from unittest.mock import patch

from api_app.analyzers_manager.observable_analyzers.threatstream import Threatstream
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)
from tests.mock_utils import MockUpResponse


class ThreatstreamTestCase(BaseAnalyzerTest):
    analyzer_class = Threatstream

    @staticmethod
    def get_mocked_response():
        mock_response = {
            "objects": [
                {
                    "id": 123456,
                    "value": "example.com",
                    "type": "domain",
                    "confidence": 95,
                    "status": "active",
                    "source": "ThreatStream",
                }
            ]
        }

        return patch(
            "api_app.analyzers_manager.observable_analyzers.threatstream.requests.get",
            return_value=MockUpResponse(mock_response, 200),
        )

    @classmethod
    def get_extra_config(cls) -> dict:
        return {
            "threatstream_analysis": "intelligence",  # Or: "confidence", "passive_dns"
            "limit": "10",
            "must_active": True,
            "minimal_confidence": "70",
            "modified_after": "2023-01-01T00:00:00",
            "_api_key_name": "test_api_key",
            "_api_user_name": "test_user",
        }
