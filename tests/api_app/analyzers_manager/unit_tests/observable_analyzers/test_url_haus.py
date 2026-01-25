from unittest.mock import patch

from api_app.analyzers_manager.observable_analyzers.urlhaus import URLHaus
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)
from tests.mock_utils import MockUpResponse


class URLHausTestCase(BaseAnalyzerTest):
    analyzer_class = URLHaus

    @staticmethod
    def get_mocked_response():
        return patch(
            "requests.post",
            return_value=MockUpResponse({"query_status": "ok", "data": []}, 200),
        )

    @classmethod
    def get_extra_config(cls):
        return {"_api_key_name": "dummy_key"}  # Used in authentication_header
