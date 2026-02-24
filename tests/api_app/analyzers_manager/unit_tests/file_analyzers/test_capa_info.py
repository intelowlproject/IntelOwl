import subprocess
from unittest.mock import patch

from api_app.analyzers_manager.file_analyzers.capa_info import CapaInfo

from .base_test_class import BaseFileAnalyzerTest


class TestCapaInfoAnalyzer(BaseFileAnalyzerTest):
    analyzer_class = CapaInfo

    def get_mocked_response(self):
        response_from_command = subprocess.CompletedProcess(
            args=[
                "capa",
                "--quiet",
                "--json",
                "-r",
                "/opt/deploy/files_required/capa/capa-rules",
                "-s",
                "/opt/deploy/files_required/capa/sigs",
                "/opt/deploy/files_required/06ebf06587b38784e2af42dd5fbe56e5",
            ],
            returncode=0,
            stdout='{"meta": {}, "rules": {"contain obfuscated stackstrings": {}, "enumerate PE sections":{}}}',
            stderr="",
        )
        return [
            patch.object(CapaInfo, "update", return_value=True),
            patch("subprocess.run", return_value=response_from_command),
        ]

    def get_extra_config(self):
        return {
            "shellcode": False,
            "arch": "64",
            "timeout": 15,
            "force_pull_signatures": False,
        }
