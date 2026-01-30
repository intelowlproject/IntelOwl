from unittest.mock import patch

from api_app.analyzers_manager.observable_analyzers.pulsedive import Pulsedive
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)
from tests.mock_utils import MockUpResponse


class PulsediveTestCase(BaseAnalyzerTest):
    analyzer_class = Pulsedive

    @staticmethod
    def get_mocked_response():
        return [
            patch(
                "requests.get",
                side_effect=[
                    MockUpResponse({}, 404),  # First call returns 404 -> triggers submission
                    MockUpResponse(
                        {"status": "done", "data": {"indicator": "example.com"}}, 200
                    ),  # Polling result
                ],
            ),
            patch("requests.post", return_value=MockUpResponse({"qid": 1}, 200)),
        ]

    @classmethod
    def get_extra_config(cls) -> dict:
        return {"scan_mode": "active", "_api_key_name": "test_api_key", "probe": 1}
