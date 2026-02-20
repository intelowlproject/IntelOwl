from unittest.mock import patch

from api_app.analyzers_manager.observable_analyzers.vulners import Vulners
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)
from tests.mock_utils import MockUpResponse


class VulnersTestCase(BaseAnalyzerTest):
    analyzer_class = Vulners

    @staticmethod
    def get_mocked_response():
        return patch(
            "requests.post",
            return_value=MockUpResponse({"result": "OK", "data": {"score": [6.5, "NONE"]}}, 200),
        )

    @classmethod
    def get_extra_config(cls):
        return {"_api_key_name": "dummy_key", "score_AI": True}
