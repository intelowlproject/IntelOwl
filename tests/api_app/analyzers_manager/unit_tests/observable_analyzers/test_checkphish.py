from unittest.mock import patch

from api_app.analyzers_manager.observable_analyzers.checkphish import CheckPhish
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)
from tests.mock_utils import MockUpResponse


class CheckPhishTestCase(BaseAnalyzerTest):
    analyzer_class = CheckPhish

    @staticmethod
    def get_mocked_response():
        return patch(
            "requests.post",
            side_effect=[
                MockUpResponse({"jobID": "sample job ID"}, 200),
                MockUpResponse({"status": "DONE"}, 200),
            ],
        )

    @classmethod
    def get_extra_config(cls) -> dict:
        return {
            "_api_key_name": "test_api_key",
            "polling_tries": 3,
            "polling_time": 1.0,
        }
