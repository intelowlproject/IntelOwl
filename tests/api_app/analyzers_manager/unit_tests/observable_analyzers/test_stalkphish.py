from unittest.mock import patch

from api_app.analyzers_manager.observable_analyzers.stalkphish import Stalkphish
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)
from tests.mock_utils import MockUpResponse


class StalkphishTestCase(BaseAnalyzerTest):
    analyzer_class = Stalkphish

    @staticmethod
    def get_mocked_response():
        return patch(
            "requests.get",
            return_value=MockUpResponse({"sample": "data"}, 200),
        )

    @classmethod
    def get_extra_config(cls) -> dict:
        return {
            "_api_key_name": "dummy",
        }
