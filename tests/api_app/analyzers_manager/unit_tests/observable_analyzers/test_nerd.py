from unittest.mock import patch

from api_app.analyzers_manager.observable_analyzers.nerd import NERD
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)
from tests.mock_utils import MockUpResponse


class NERDTestCase(BaseAnalyzerTest):
    analyzer_class = NERD

    @staticmethod
    def get_mocked_response():
        return patch(
            "requests.get",
            return_value=MockUpResponse(
                {
                    "ip": "8.8.8.8",
                    "status": "active",
                    "as": {"asn": 15169, "name": "Google LLC"},
                    "history": {},
                },
                200,
            ),
        )

    @classmethod
    def get_extra_config(cls) -> dict:
        return {
            "_api_key_name": "Bearer mock-api-key",
            "nerd_analysis": "basic",  # Options: basic, full, rep, fmp
        }
