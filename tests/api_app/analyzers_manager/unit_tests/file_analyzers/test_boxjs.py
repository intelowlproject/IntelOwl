from unittest.mock import patch

from api_app.analyzers_manager.file_analyzers.boxjs_scan import BoxJS
from tests.api_app.analyzers_manager.unit_tests.file_analyzers.base_test_class import (
    BaseFileAnalyzerTest,
)


class BoxJSTestCase(BaseFileAnalyzerTest):
    analyzer_class = BoxJS

    @staticmethod
    def get_mocked_response():
        # Mock a typical BoxJS analysis report
        mock_report = {
            "analysis": {
                "time": "2024-06-22T10:30:00Z",
                "timeout": False,
                "killed": False,
            },
            "snippets": [
                {
                    "code": "eval(atob('bWFsaWNpb3VzX2NvZGU='))",
                    "line": 15,
                    "file": "malicious.js",
                }
            ],
            "urls.json": [
                "http://malicious-domain.com/payload",
                "https://evil-site.net/download",
            ],
            "active_urls.json": ["http://c2-server.evil/beacon"],
            "IOC.json": [
                {"type": "url", "value": {"url": "http://bad-actor.com/steal-data"}},
                {"type": "domain", "value": {"domain": "malware-host.net"}},
            ],
            "resources": {
                "files_created": [],
                "files_modified": [],
                "network_connections": 3,
            },
            "runtime_info": {
                "execution_time": 8.5,
                "memory_usage": "45MB",
                "api_calls": 127,
            },
        }

        return patch(
            "api_app.analyzers_manager.file_analyzers.boxjs_scan.BoxJS._docker_run",
            return_value=mock_report,
        )
