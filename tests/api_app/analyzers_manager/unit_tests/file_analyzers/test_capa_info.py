from unittest.mock import patch

from api_app.analyzers_manager.file_analyzers.capa_info import CapaInfo

from .base_test_class import BaseFileAnalyzerTest


class TestCapaInfoAnalyzer(BaseFileAnalyzerTest):
    analyzer_class = CapaInfo

    def get_mocked_response(self):
        mock_response = {
            "rules": [
                {"name": "create process", "namespace": "host-interaction/process"},
                {"name": "read file", "namespace": "host-interaction/file"},
            ],
            "meta": {"analysis": "mocked capa analysis"},
        }
        return patch.object(CapaInfo, "_docker_run", return_value=mock_response)

    def get_extra_config(self):
        return {
            "shellcode": False,
            "arch": "64",
            "args": [],
        }
