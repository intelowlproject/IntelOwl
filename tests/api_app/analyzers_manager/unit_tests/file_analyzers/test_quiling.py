from unittest.mock import patch

from api_app.analyzers_manager.file_analyzers.qiling import Qiling

from .base_test_class import BaseFileAnalyzerTest


class TestQilingAnalyzer(BaseFileAnalyzerTest):
    analyzer_class = Qiling

    def get_mocked_response(self):
        # Mocked successful qiling response
        mock_response = {
            "trace": ["instruction1", "instruction2"],
            "syscalls": ["open", "read", "write"],
            "meta": {"analysis": "mocked qiling analysis"},
        }
        return patch.object(Qiling, "_docker_run", return_value=mock_response)

    def get_extra_config(self):
        # Example runtime config override
        return {
            "os": "linux",
            "arch": "x86_64",
            "shellcode": False,
            "profile": "",
            "args": [],
        }
