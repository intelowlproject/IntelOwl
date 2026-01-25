from unittest.mock import patch

from api_app.analyzers_manager.observable_analyzers.cycat import CyCat
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)
from tests.mock_utils import MockUpResponse


class CyCatTestCase(BaseAnalyzerTest):
    analyzer_class = CyCat

    @staticmethod
    def get_mocked_response():
        mock_response = {
            "title": "Test Rule",
            "description": "Test description",
            "_cycat_type": "Item",
        }

        return patch("requests.get", return_value=MockUpResponse(mock_response, 200))

    @classmethod
    def get_extra_config(cls) -> dict:
        return {"url": "https://api.cycat.org"}
