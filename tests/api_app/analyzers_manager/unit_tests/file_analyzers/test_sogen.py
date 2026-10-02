from unittest.mock import MagicMock, patch

from api_app.analyzers_manager.file_analyzers.sogen import Sogen

from .base_test_class import BaseFileAnalyzerTest


class TestSogenAnalyzer(BaseFileAnalyzerTest):
    analyzer_class = Sogen

    def get_mocked_response(self):
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "module_loads": [{"name": "sample.exe", "entry_point": "0x1000"}],
            "entry_point_hit": True,
            "exit_status": 0,
            "error": None,
        }
        return patch("requests.post", return_value=mock_response)

    def get_extra_config(self):
        return {
            "max_instructions": 1000,
            "timeout_seconds": 10,
            "requests_timeout": 30,
            "url_key_name": "http://sogen_analyzer:4009",
        }
