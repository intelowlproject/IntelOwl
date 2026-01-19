from unittest.mock import patch

from api_app.analyzers_manager.file_analyzers.docguard import DocGuardUpload
from tests.mock_utils import MockUpResponse

from .base_test_class import BaseFileAnalyzerTest


class TestDocGuardUpload(BaseFileAnalyzerTest):
    analyzer_class = DocGuardUpload

    def get_extra_config(self):
        # Provide API key configuration for testing
        return {"_api_key_name": "test_api_key_12345"}

    def get_mocked_response(self):
        # Mock the requests.post call to DocGuard API
        mock_response = MockUpResponse(
            {
                "status": "success",
                "analysis_id": "12345-abcde-67890",
                "file_info": {
                    "filename": "test_file.pdf",
                    "file_size": 1024,
                    "file_type": "PDF",
                },
                "scan_results": {
                    "threats_detected": 0,
                    "risk_level": "low",
                    "scan_time": "2025-01-15T10:30:00Z",
                },
                "details": {
                    "malware_detected": False,
                    "suspicious_content": False,
                    "document_structure": "valid",
                },
            },
            200,
        )

        return patch("requests.post", return_value=mock_response)
