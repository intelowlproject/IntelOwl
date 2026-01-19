from unittest.mock import MagicMock, patch

from api_app.analyzers_manager.file_analyzers.intezer_scan import IntezerScan

from .base_test_class import BaseFileAnalyzerTest


class TestIntezerScan(BaseFileAnalyzerTest):
    analyzer_class = IntezerScan

    def get_extra_config(self):
        return {
            "soft_time_limit": 120,
            "disable_dynamic_unpacking": True,
            "disable_static_unpacking": True,
            "_api_key_name": "dummy",
            "poll_interval": 5,
            "timeout": 115,
        }

    def get_mocked_response(self):
        mock_analysis = MagicMock()
        mock_analysis.result.return_value = {
            "analysis_url": "https://analyze.intezer.com/sample",
            "verdict": "malicious",
            "family_name": "SomeMalwareFamily",
        }

        return [
            patch(
                "api_app.analyzers_manager.file_analyzers.intezer_scan.FileAnalysis",
                return_value=mock_analysis,
            )
        ]
