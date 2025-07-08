from unittest.mock import patch

from api_app.analyzers_manager.observable_analyzers.koodous import Koodous
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)
from tests.mock_utils import MockUpResponse


class KoodousTestCase(BaseAnalyzerTest):
    analyzer_class = Koodous

    @staticmethod
    def get_mocked_response():
        return patch("requests.get", return_value=MockUpResponse({"ok": True}, 200))

    @classmethod
    def get_extra_config(cls):
        return {"_api_key_name": "token"}
