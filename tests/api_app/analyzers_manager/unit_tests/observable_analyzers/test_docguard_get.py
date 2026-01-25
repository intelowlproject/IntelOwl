from unittest.mock import patch

from api_app.analyzers_manager.observable_analyzers.docguard_get import DocGuard_Hash
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)
from tests.mock_utils import MockUpResponse


class DocGuardHashTestCase(BaseAnalyzerTest):
    analyzer_class = DocGuard_Hash

    @staticmethod
    def get_mocked_response():
        mock_result = {
            "status": "success",
            "hash_type": "sha256",
            "threat_level": "low",
            "file_info": {"filename": "test.pdf", "size": 123456},
        }
        return patch("requests.get", return_value=MockUpResponse(mock_result, 200))

    @classmethod
    def get_extra_config(cls) -> dict:
        return {"_api_key_name": "mocked_docguard_api_key"}
