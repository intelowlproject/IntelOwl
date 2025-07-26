from unittest.mock import patch

from api_app.analyzers_manager.file_analyzers.strings_info import StringsInfo

from .base_test_class import BaseFileAnalyzerTest


class TestStringsInfo(BaseFileAnalyzerTest):
    analyzer_class = StringsInfo

    def get_extra_config(self):
        return {
            "max_number_of_strings": 100,
            "max_characters_for_string": 200,
            "rank_strings": 1,  # Enable string ranking
        }

    def get_mocked_response(self):
        # Mock strings extracted from binary
        mock_strings_first_call = [
            "http://malicious-site.com/payload",
            "CreateFileA",
            "WriteFile",
            "RegSetValueA",
            "https://c2server.evil/beacon",
            "malware.exe",
            "C:\\Windows\\System32\\cmd.exe",
            "ftp://badsite.com/data",
            "Some random string",
            "Another test string",
        ]

        # Mock ranked strings (second call when rank_strings is enabled)
        mock_ranked_strings = [
            "http://malicious-site.com/payload",
            "https://c2server.evil/beacon",
            "CreateFileA",
            "ftp://badsite.com/data",
            "WriteFile",
            "RegSetValueA",
            "malware.exe",
            "C:\\Windows\\System32\\cmd.exe",
        ]

        return [
            patch(
                "api_app.analyzers_manager.file_analyzers.strings_info.StringsInfo._docker_run",
                side_effect=[
                    mock_strings_first_call,  # First call for flarestrings
                    mock_ranked_strings,  # Second call for rank_strings (if enabled)
                ],
            ),
        ]
