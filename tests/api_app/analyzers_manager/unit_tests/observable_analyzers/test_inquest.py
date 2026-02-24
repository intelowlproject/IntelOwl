from unittest.mock import patch

from api_app.analyzers_manager.observable_analyzers.inquest import InQuest
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)
from tests.mock_utils import MockUpResponse


class InQuestTestCase(BaseAnalyzerTest):
    analyzer_class = InQuest

    @staticmethod
    def get_mocked_response():
        mock_response = {"result": "ok", "data": ["some IOC result"]}
        return patch("requests.get", return_value=MockUpResponse(mock_response, 200))

    @classmethod
    def get_extra_config(cls) -> dict:
        return {
            "inquest_analysis": "dfi_search",
            "_api_key_name": "Bearer dummy_api_key",
            "generic_identifier_mode": "user-defined",
        }
