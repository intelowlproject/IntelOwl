from unittest.mock import patch

from api_app.analyzers_manager.observable_analyzers.virushee import VirusheeCheckHash
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)
from tests.mock_utils import MockUpResponse


class VirusheeCheckHashTestCase(BaseAnalyzerTest):
    analyzer_class = VirusheeCheckHash

    @staticmethod
    def get_mocked_response():
        return patch("requests.Session.get", return_value=MockUpResponse({"success": True}, 200))

    @classmethod
    def get_extra_config(cls):
        return {"_api_key_name": "dummy_api_key"}
