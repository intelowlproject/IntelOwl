from unittest.mock import patch

from api_app.analyzers_manager.observable_analyzers.spyse import Spyse
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)
from tests.mock_utils import MockUpResponse


class SpyseTestCase(BaseAnalyzerTest):
    analyzer_class = Spyse

    @staticmethod
    def get_mocked_response():
        mock_response = {
            "status": "ok",
            "data": {
                "id": "example-id",
                "attributes": {
                    "ip": "8.8.8.8",
                    "location": {"country": "US"},
                    "as": {"asn": 15169, "name": "GOOGLE"},
                },
            },
        }
        return patch(
            "requests.get",
            return_value=MockUpResponse(mock_response, 200),
        )

    @classmethod
    def get_extra_config(cls) -> dict:
        return {"_api_key_name": "fake_spyse_api_key"}
