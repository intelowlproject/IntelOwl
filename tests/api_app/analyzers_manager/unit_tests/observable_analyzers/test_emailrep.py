from unittest.mock import patch

from api_app.analyzers_manager.observable_analyzers.emailrep import EmailRep
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)
from tests.mock_utils import MockUpResponse


class EmailRepTestCase(BaseAnalyzerTest):
    analyzer_class = EmailRep

    @staticmethod
    def get_mocked_response():
        return patch("requests.get", return_value=MockUpResponse(json_data={}, status_code=200))

    @classmethod
    def get_extra_config(cls) -> dict:
        # Optional API key; mock something if needed
        return {"_api_key_name": "mock-api-key"}
