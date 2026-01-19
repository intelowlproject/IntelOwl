from unittest.mock import MagicMock, patch

from api_app.analyzers_manager.file_analyzers.signature_info import SignatureInfo

from .base_test_class import BaseFileAnalyzerTest


class TestSignatureInfo(BaseFileAnalyzerTest):
    analyzer_class = SignatureInfo

    def get_extra_config(self):
        return {}

    def get_mocked_response(self):
        # Create mock process
        mock_process = MagicMock()
        mock_process.returncode = 0
        mock_process.communicate.return_value = (
            b"Signature verification: ok\nCertificate info:\n  Subject: CN=Test Certificate\n  Issuer: CN=Test CA\n",
            b"",
        )

        return [
            patch(
                "api_app.analyzers_manager.file_analyzers.signature_info.Popen",
                return_value=mock_process,
            ),
            patch(
                "api_app.analyzers_manager.file_analyzers.signature_info.settings.PROJECT_LOCATION",
                "/mock/project",
            ),
        ]
