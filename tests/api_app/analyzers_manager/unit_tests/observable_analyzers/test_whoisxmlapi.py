from unittest.mock import patch

from api_app.analyzers_manager.observable_analyzers.whoisxmlapi import Whoisxmlapi
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)
from tests.mock_utils import MockUpResponse


class WhoisxmlapiTestCase(BaseAnalyzerTest):
    analyzer_class = Whoisxmlapi

    @staticmethod
    def get_mocked_response():
        mock_response = {
            "WhoisRecord": {
                "domainName": "example.com",
                "registrarName": "Example Registrar",
                "createdDate": "2000-01-01T00:00:00Z",
            }
        }

        return patch("requests.get", return_value=MockUpResponse(mock_response, 200))

    @classmethod
    def get_extra_config(cls) -> dict:
        return {"_api_key_name": "test_api_key"}
