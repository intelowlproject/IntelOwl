from unittest.mock import patch

from api_app.analyzers_manager.observable_analyzers.onionscan import Onionscan
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)


class OnionscanTestCase(BaseAnalyzerTest):
    analyzer_class = Onionscan

    @staticmethod
    def get_mocked_response():
        mock_response = {
            "data": {
                "hiddenService": "http://exampleonion.onion",
                "webDetected": True,
                "webServerFingerprint": "nginx",
                "relatedServices": ["IRC", "FTP"],
                "pgpKeys": [],
                "sshKey": None,
            }
        }

        return patch(
            "api_app.analyzers_manager.classes.DockerBasedAnalyzer._docker_run",
            return_value=mock_response,
        )

    @classmethod
    def get_extra_config(cls) -> dict:
        return {"verbose": True, "tor_proxy_address": "127.0.0.1:9050"}
