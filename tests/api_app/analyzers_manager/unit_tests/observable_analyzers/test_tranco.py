from unittest.mock import patch

from api_app.analyzers_manager.observable_analyzers.tranco import Tranco
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)
from tests.mock_utils import MockUpResponse


class TrancoTestCase(BaseAnalyzerTest):
    analyzer_class = Tranco

    @staticmethod
    def get_mocked_response():
        mock_data = {"rank": 12345, "domain": "example.com", "date": "2025-07-18"}

        return patch("requests.get", return_value=MockUpResponse(mock_data, 200))

    @classmethod
    def get_extra_config(cls) -> dict:
        return {}
