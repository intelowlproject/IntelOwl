import subprocess
from unittest.mock import patch

from api_app.analyzers_manager.file_analyzers.floss import Floss

from .base_test_class import BaseFileAnalyzerTest


class TestFloss(BaseFileAnalyzerTest):
    analyzer_class = Floss

    def get_extra_config(self):
        return {
            "max_no_of_strings": {"decoded_strings": 10, "stack_strings": 5},
            "rank_strings": {"decoded_strings": True, "stack_strings": False},
        }

    def get_mocked_response(self):

        response_from_command = subprocess.CompletedProcess(
            args=[
                "floss",
                "--json",
                "--no",
                "static",
                "--",
                "/opt/deploy/files_required/06ebf06587b38784e2af42dd5fbe56e5",
            ],
            returncode=0,
            stdout='{"metadata": {}, "analysis": {}, "strings": {"decoded_strings":["de_string2", "de_string1"],"stack_strings":[]}}',
            stderr="",
        )

        return [
            patch("subprocess.run", return_value=response_from_command),
            patch(
                "api_app.analyzers_manager.file_analyzers.floss.Floss._docker_run",
                return_value=["de_string1", "de_string2"],  # simulating ranked strings
            ),
        ]
