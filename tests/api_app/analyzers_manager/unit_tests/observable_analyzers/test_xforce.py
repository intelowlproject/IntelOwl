from unittest.mock import patch

from api_app.analyzers_manager.observable_analyzers.xforce import XForce
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)
from tests.mock_utils import MockUpResponse


class XForceTestCase(BaseAnalyzerTest):
    analyzer_class = XForce

    @staticmethod
    def get_mocked_response():
        mock_response = {
            "score": 5,
            "categoryDescriptions": {"Search Engines": "Sites that provide a way to search the internet."},
        }
        return patch("requests.get", return_value=MockUpResponse(mock_response, 200))

    @classmethod
    def get_extra_config(cls) -> dict:
        return {
            "_api_key_name": "test_key",
            "_api_password_name": "test_pass",
            "malware_only": False,
            "timeout": 5,
        }
