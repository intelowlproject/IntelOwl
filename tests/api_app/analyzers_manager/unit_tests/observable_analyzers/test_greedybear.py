from unittest.mock import patch

from api_app.analyzers_manager.observable_analyzers.greedybear import GreedyBear
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)
from tests.mock_utils import MockUpResponse


class GreedyBearTestCase(BaseAnalyzerTest):
    analyzer_class = GreedyBear

    @classmethod
    def get_extra_config(cls):
        return {"url": "https://api.greedybear.io", "_api_key_name": "demo_token"}

    @staticmethod
    def get_mocked_response():
        return patch(
            "requests.get",
            return_value=MockUpResponse({"success": True, "data": {}}, 200),
        )
