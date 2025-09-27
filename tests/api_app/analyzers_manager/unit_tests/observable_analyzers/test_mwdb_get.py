from unittest.mock import patch

from api_app.analyzers_manager.file_analyzers.mwdb_scan import mocked_mwdb_response
from api_app.analyzers_manager.observable_analyzers.mwdb_get import MWDBGet
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)


class MWDBGetTestCase(BaseAnalyzerTest):
    analyzer_class = MWDBGet

    @staticmethod
    def get_mocked_response():
        return patch("mwdblib.MWDB", side_effect=mocked_mwdb_response)

    @classmethod
    def get_extra_config(cls) -> dict:
        return {"_api_key_name": "mocked_mwdb_api_key"}
