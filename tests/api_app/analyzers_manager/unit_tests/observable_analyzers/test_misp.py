from unittest.mock import patch

from api_app.analyzers_manager.observable_analyzers.misp import MISP
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)
from tests.mock_utils import MockResponseNoOp


class MISPTestCase(BaseAnalyzerTest):
    analyzer_class = MISP

    @staticmethod
    def get_mocked_response():
        return patch("pymisp.PyMISP", return_value=MockResponseNoOp({"response": "mocked"}, 200))

    @classmethod
    def get_extra_config(cls) -> dict:
        return {
            "_api_key_name": "test_api_key",
            "_url_key_name": "https://misp.local",
            "ssl_check": False,
            "self_signed_certificate": False,
            "debug": False,
            "from_days": 30,
            "limit": 10,
            "enforce_warninglist": False,
            "filter_on_type": True,
            "strict_search": False,
            "published": True,
            "metadata": False,
        }
