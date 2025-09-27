from unittest.mock import patch

from api_app.analyzers_manager.file_analyzers.thug_file import ThugFile

from .base_test_class import BaseFileAnalyzerTest


class TestThugFile(BaseFileAnalyzerTest):
    analyzer_class = ThugFile

    def get_extra_config(self):
        return {
            "user_agent": "winxpie60",
            "dom_events": "click,submit",
            "use_proxy": True,
            "proxy": "http://proxy.example.com:8080",
            "enable_awis": True,
            "enable_image_processing_analysis": False,
        }

    def get_mocked_response(self):
        # Mock Thug analysis results for malicious file analysis
        mock_thug_report = {
            "analysis": {
                "datetime": "2024-01-15 10:30:45",
                "url": "file://sample.html",
                "logtype": "thug",
                "version": "0.9.0",
            },
        }

        return [
            patch(
                "api_app.analyzers_manager.file_analyzers.thug_file.ThugFile._docker_run",
                return_value=mock_thug_report,
            ),
            patch(
                "api_app.analyzers_manager.file_analyzers.thug_file.secrets.token_hex",
                return_value="abc123",
            ),
        ]
