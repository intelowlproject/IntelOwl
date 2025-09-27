from unittest.mock import patch

from api_app.analyzers_manager.observable_analyzers.intelx import IntelX
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)
from tests.mock_utils import MockUpResponse


class IntelXTestCase(BaseAnalyzerTest):
    analyzer_class = IntelX

    @staticmethod
    def get_mocked_response():
        return [
            patch("requests.Session.post", return_value=MockUpResponse({"id": 1}, 200)),
            patch(
                "requests.Session.get",
                return_value=MockUpResponse({"selectors": []}, 200),
            ),
        ]

    @classmethod
    def get_extra_config(cls) -> dict:
        return {
            "_api_key_name": "dummy_api_key",
            "query_type": "phonebook",  # or "intelligent"
            "rows_limit": 10,
            "max_tries": 3,
            "poll_distance": 1,
            "timeout": 5,
            "datefrom": "2024-01-01",
            "dateto": "2024-12-31",
            "search_url": "",
        }
