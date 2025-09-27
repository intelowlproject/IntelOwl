from unittest.mock import patch

from api_app.analyzers_manager.observable_analyzers.hunter_io import Hunter_Io
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)
from tests.mock_utils import MockUpResponse


class HunterIoTestCase(BaseAnalyzerTest):
    analyzer_class = Hunter_Io

    @staticmethod
    def get_mocked_response():
        mock_response = {
            "data": {
                "domain": "example.com",
                "emails": [{"value": "test@example.com", "type": "generic"}],
            }
        }
        return patch("requests.get", return_value=MockUpResponse(mock_response, 200))

    @classmethod
    def get_extra_config(cls) -> dict:
        return {"_api_key_name": "dummy_api_key"}
