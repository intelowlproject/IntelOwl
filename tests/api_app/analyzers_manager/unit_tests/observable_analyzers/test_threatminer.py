from unittest.mock import patch

from api_app.analyzers_manager.observable_analyzers.threatminer import Threatminer
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)
from tests.mock_utils import MockUpResponse


class ThreatminerTestCase(BaseAnalyzerTest):
    analyzer_class = Threatminer

    @staticmethod
    def get_mocked_response():
        mock_response = {"status_code": 200, "results": ["example result"]}

        return patch("requests.get", return_value=MockUpResponse(mock_response, 200))

    @classmethod
    def get_extra_config(cls) -> dict:
        return {"rt_value": "1"}  # or another valid test value if needed
