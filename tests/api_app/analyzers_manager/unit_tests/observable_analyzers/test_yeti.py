from unittest.mock import patch

from api_app.analyzers_manager.observable_analyzers.yeti import YETI
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)
from tests.mock_utils import MockUpResponse


class YETITestCase(BaseAnalyzerTest):
    analyzer_class = YETI

    @staticmethod
    def get_mocked_response():
        mock_response = [
            {
                "id": "123",
                "value": "example.com",
                "type": "domain",
                "source": "malwaredb",
            }
        ]
        return patch("requests.post", return_value=MockUpResponse(mock_response, 200))

    @classmethod
    def get_extra_config(cls) -> dict:
        return {
            "_url_key_name": "https://yeti.example.com",
            "_api_key_name": "test_yeti_api_key",
            "verify_ssl": False,
            "results_count": 10,
            "regex": False,
        }
