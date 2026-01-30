from unittest.mock import patch

from api_app.analyzers_manager.observable_analyzers.robtex import Robtex
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)
from tests.mock_utils import MockUpResponse


class RobtexTestCase(BaseAnalyzerTest):
    analyzer_class = Robtex

    @staticmethod
    def get_mocked_response():
        mock_text = '{"test1":"test1"}\r\n{"test2":"test2"}'
        return patch("requests.get", return_value=MockUpResponse({}, 200, text=mock_text))

    @classmethod
    def get_extra_config(cls) -> dict:
        return {}
