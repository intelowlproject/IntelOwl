from unittest.mock import patch

from api_app.analyzers_manager.file_analyzers.malpedia_scan import MalpediaScan
from tests.mock_utils import MockUpResponse

from .base_test_class import BaseFileAnalyzerTest


class TestMalpediaScan(BaseFileAnalyzerTest):
    analyzer_class = MalpediaScan

    def get_extra_config(self):
        return {"_api_key_name": "test_api_key_dummy"}

    def get_mocked_response(self):
        # Patch the requests.post to simulate API call
        return patch(
            "requests.post",
            return_value=MockUpResponse(
                {
                    "scan_id": "abc123",
                    "results": [],
                    "status": "success",
                },
                200,
            ),
        )
