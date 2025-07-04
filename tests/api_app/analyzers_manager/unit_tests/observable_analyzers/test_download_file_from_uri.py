# tests/api_app/analyzers_manager/unit_tests/observable_analyzers/test_download_file.py

from unittest.mock import patch

from api_app.analyzers_manager.observable_analyzers.download_file_from_uri import (
    DownloadFileFromUri,
)
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)
from tests.mock_utils import MockUpResponse


class DownloadFileFromUriTestCase(BaseAnalyzerTest):
    analyzer_class = DownloadFileFromUri

    @staticmethod
    def get_mocked_response():
        # Simulate a binary response with application/octet-stream content
        return patch(
            "requests.get",
            return_value=MockUpResponse(
                json_data={},  # Required dummy arg
                content=b"test binary content",
                status_code=200,
                headers={"Content-Type": "application/octet-stream"},
            ),
        )

    @classmethod
    def get_extra_config(cls):
        return {
            "_http_proxy": "",
            "header_user_agent": "IntelOwlTestAgent",
            "header_cookies": "",
            "header_content_type": "application/octet-stream",
            "header_accept": "*/*",
            "timeout": 5,
        }
