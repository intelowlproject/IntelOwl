from unittest.mock import patch

from api_app.analyzers_manager.observable_analyzers.ipinfo import IPInfo
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)
from tests.mock_utils import MockUpResponse


class IPInfoTestCase(BaseAnalyzerTest):
    analyzer_class = IPInfo

    @staticmethod
    def get_mocked_response():
        mock_response = {
            "ip": "8.8.8.8",
            "city": "Mountain View",
            "region": "California",
            "country": "US",
            "loc": "37.3860,-122.0838",
            "org": "AS15169 Google LLC",
        }

        return patch("requests.get", return_value=MockUpResponse(mock_response, 200))

    @classmethod
    def get_extra_config(cls) -> dict:
        return {"_api_key_name": "dummy_token"}
