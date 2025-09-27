from unittest.mock import patch

from api_app.analyzers_manager.file_analyzers.peframe import PEframe

from .base_test_class import BaseFileAnalyzerTest


class PEframeTest(BaseFileAnalyzerTest):
    analyzer_class = PEframe

    def get_mocked_response(self):
        """
        Mock the _docker_run method since PEframe is a DockerBasedAnalyzer
        that makes HTTP requests to a containerized PEframe service
        """
        # Mock realistic PEframe analysis result
        mock_peframe_result = {
            "info": {
                "file": "test_file.exe",
                "size": 1024000,
                "md5": "1234567890abcdef1234567890abcdef",
                "sha1": "abcdef1234567890abcdef1234567890abcdef12",
                "sha256": "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef12",
            }
        }

        return patch.object(PEframe, "_docker_run", return_value=mock_peframe_result)

    def get_extra_config(self) -> dict:
        """
        PEframe analyzer configuration
        """
        return {
            "url": "http://malware_tools_analyzers:4002/peframe",
            "max_tries": 25,
            "poll_distance": 5,
            "timeout": 540,  # 60 * 9
        }
