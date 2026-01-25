from unittest.mock import patch

from api_app.analyzers_manager.observable_analyzers.filescan_search import (
    FileScanSearch,
)
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)
from tests.mock_utils import MockUpResponse


class FileScanSearchTestCase(BaseAnalyzerTest):
    analyzer_class = FileScanSearch

    @staticmethod
    def get_mocked_response():
        return patch(
            "requests.get",
            return_value=MockUpResponse(
                {
                    "items": [],
                    "count": 0,
                    "count_search_params": 1,
                    "method": "and",
                },
                200,
            ),
        )

    @classmethod
    def get_extra_config(cls):
        return {"_api_key": "dummy-key"}
