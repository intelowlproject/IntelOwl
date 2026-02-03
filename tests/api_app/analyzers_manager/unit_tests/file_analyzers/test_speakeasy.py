from unittest.mock import MagicMock, patch

from api_app.analyzers_manager.file_analyzers.speakeasy_emulation import SpeakEasy

from .base_test_class import BaseFileAnalyzerTest


class TestSpeakEasyAnalyzer(BaseFileAnalyzerTest):
    analyzer_class = SpeakEasy

    def get_mocked_response(self):
        mock_speakeasy = MagicMock()
        mock_speakeasy.load_shellcode.return_value = 0x1000
        mock_speakeasy.load_module.return_value = "mock_module"
        mock_speakeasy.get_report.return_value = {
            "api_calls": ["CreateFile", "WriteFile"],
            "summary": "Mocked speakeasy analysis",
        }

        return patch("speakeasy.Speakeasy", return_value=mock_speakeasy)

    def get_extra_config(self):
        return {
            "shellcode": False,
            "arch": "x86",
            "raw_offset": 0,
            "args": [],
        }
