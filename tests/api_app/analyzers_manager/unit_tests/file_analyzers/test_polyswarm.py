from unittest.mock import MagicMock, patch

from api_app.analyzers_manager.file_analyzers.polyswarm import Polyswarm

from .base_test_class import BaseFileAnalyzerTest


class TestPolyswarm(BaseFileAnalyzerTest):
    analyzer_class = Polyswarm

    def get_mocked_response(self):
        """
        Mock the PolyswarmAPI to return a consistent analysis result
        without making actual API calls.
        """
        # Create a mock result object that mimics the structure
        # returned by PolyswarmAPI.wait_for()
        mock_result = MagicMock()
        mock_result.failed = False
        mock_result.polyscore = 0.33460048640798623
        mock_result.sha256 = ""
        mock_result.md5 = "76deca20806c16df50ffeda163fd50e9"
        mock_result.sha1 = "99ff1cd17aea94feb355e7bdb01e9f788a4971bb"
        mock_result.extended_type = "GIF image data, version 89a, 821 x 500"
        mock_result.first_seen.isoformat.return_value = "2024-07-27T20:20:12.121980"
        mock_result.last_seen.isoformat.return_value = "2024-07-27T20:20:12.121980"
        mock_result.permalink = ""

        # Mock assertions list
        mock_assertions = []
        engines = [
            "Kaspersky",
            "Qihoo 360",
            "XVirus",
            "SecureAge",
            "DrWeb",
            "Proton",
            "Electron",
            "Filseclab",
            "ClamAV",
            "SecondWrite",
            "Ikarus",
            "NanoAV",
            "Alibaba",
        ]

        for engine in engines:
            mock_assertion = MagicMock()
            mock_assertion.author_name = engine
            mock_assertion.verdict = False  # All benign
            mock_assertions.append(mock_assertion)

        mock_result.assertions = mock_assertions

        # Mock the API instance
        mock_api_instance = MagicMock()
        mock_api_instance.submit.return_value = MagicMock()  # Mock instance
        mock_api_instance.wait_for.return_value = mock_result

        # Mock PolyswarmAPI constructor
        return patch(
            "api_app.analyzers_manager.file_analyzers.polyswarm.PolyswarmAPI",
            return_value=mock_api_instance,
        )

    @classmethod
    def get_extra_config(cls) -> dict:
        """Provide required configuration for Polyswarm analyzer"""
        return {
            "_api_key": "test_api_key_123",
            "timeout": 900,  # 15 minutes as in the original
            "polyswarm_community": "default",
        }
