from unittest.mock import patch

from api_app.analyzers_manager.observable_analyzers.onyphe import Onyphe
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)
from tests.mock_utils import MockUpResponse


class OnypheTestCase(BaseAnalyzerTest):
    analyzer_class = Onyphe

    @staticmethod
    def get_mocked_response():
        mock_response = {
            "ip": "8.8.8.8",
            "results": {
                "geolocation": {
                    "country_name": "United States",
                    "city": "Mountain View",
                },
                "as": {"asn": 15169, "org": "Google LLC"},
            },
        }

        return patch("requests.get", return_value=MockUpResponse(mock_response, 200))

    @classmethod
    def get_extra_config(cls) -> dict:
        return {"_api_key_name": "mock-api-key"}
