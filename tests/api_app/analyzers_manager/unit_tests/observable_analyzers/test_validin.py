from unittest.mock import patch

from api_app.analyzers_manager.observable_analyzers.validin import Validin
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)
from tests.mock_utils import MockUpResponse


class ValidinTestCase(BaseAnalyzerTest):
    analyzer_class = Validin

    @staticmethod
    def get_mocked_response():
        response = {
            "key": "191.121.10.0",
            "effective_opts": {"type": "ip4", "limit": 100, "wildcard": False},
            "status": "finished",
            "query_key": "191.121.10.0",
            "records": {},
            "records_returned": 0,
            "limited": False,
            "error": None,
        }
        return patch("requests.get", return_value=MockUpResponse(response, 200))

    @classmethod
    def get_extra_config(cls):
        return {
            "scan_choice": "default",  # or a specific key like "a_records" if needed
            "_api_key_name": "dummy_validin_token",
        }
