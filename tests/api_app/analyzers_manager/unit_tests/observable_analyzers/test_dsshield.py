from unittest.mock import patch

from api_app.analyzers_manager.observable_analyzers.dshield import DShield
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)
from tests.mock_utils import MockUpResponse


class DShieldTestCase(BaseAnalyzerTest):
    analyzer_class = DShield

    @staticmethod
    def get_mocked_response():
        return patch(
            "requests.get",
            return_value=MockUpResponse(
                json_data={},
                status_code=200,  # Required even if not used
            ),
        )

    @classmethod
    def get_extra_config(cls) -> dict:
        # No required runtime config, but must return something
        return {}
