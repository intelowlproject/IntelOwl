from unittest.mock import patch

from api_app.analyzers_manager.file_analyzers.filescan import FileScanUpload
from tests.mock_utils import MockUpResponse

from .base_test_class import BaseFileAnalyzerTest


class TestFileScanUpload(BaseFileAnalyzerTest):
    analyzer_class = FileScanUpload

    def get_extra_config(self):
        return {"_api_key": "sample_key"}

    def get_mocked_response(self):
        return [
            patch(
                "requests.post",
                return_value=MockUpResponse({"flow_id": 1}, 200),
            ),
            patch(
                "requests.get",
                return_value=MockUpResponse(
                    {
                        "allFinished": True,
                        "general": {
                            "verdict": "clean",
                            "file_type": "exe",
                            "file_name": "test_file.exe",
                        },
                        "finalVerdict": "no threat detected",
                    },
                    200,
                ),
            ),
        ]
