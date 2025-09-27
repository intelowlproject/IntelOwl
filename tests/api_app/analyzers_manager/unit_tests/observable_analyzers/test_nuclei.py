from unittest.mock import patch

from api_app.analyzers_manager.observable_analyzers.nuclei import NucleiAnalyzer
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)


class NucleiAnalyzerTestCase(BaseAnalyzerTest):
    analyzer_class = NucleiAnalyzer

    @staticmethod
    def get_mocked_response():
        mock_response = {
            "data": [
                {
                    "templateID": "cves/2022/CVE-2022-XXXXX",
                    "info": {
                        "name": "Sample CVE Test",
                        "severity": "high",
                        "description": "Mock vulnerability detected",
                    },
                    "matched-at": "https://example.com",
                }
            ]
        }

        return patch(
            "api_app.analyzers_manager.classes.DockerBasedAnalyzer._docker_run",
            return_value=mock_response,
        )

    @classmethod
    def get_extra_config(cls) -> dict:
        return {
            "template_dirs": ["cves", "http"],  # use valid dirs to avoid warnings
        }
