from unittest.mock import patch

from api_app.analyzers_manager.observable_analyzers.joesandbox import JoeSandboxAnalyzer
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)


class JoeSandboxAnalyzerTestCase(BaseAnalyzerTest):
    analyzer_class = JoeSandboxAnalyzer

    @staticmethod
    def get_mocked_response():
        analysis_info_response = {
            "webid": "100",
            "analysisid": "4",
            "status": "finished",
            "detection": "malicious",
            "score": 42,
            "classification": "",
            "threatname": "Unknown",
            "comments": "a sample comment",
            "filename": "sample.exe",
            "scriptname": "default.jbs",
            "time": "2017-08-11T16:06:32+02:00",
            "duration": 150,
            "encrypted": False,
            "md5": "0cbc6611f5540bd0809a388dc95a615b",
            "sha1": "640ab2bae07bedc4c163f679a746f7ab7fb5d1fa",
            "sha256": "532eaabd9574880 [...] 299550d7a6e0f345e25",
            "tags": ["internal", "important"],
            "live-interaction-url": "https://joesandbox.com/analysis/123456789",
            "runs": [
                {
                    "detection": "unknown",
                    "error": "Unable to run",
                    "system": "w7",
                    "yara": False,
                    "sigma": False,
                    "score": 1,
                },
                {
                    "detection": "malicious",
                    "error": None,
                    "system": "w7x64",
                    "yara": False,
                    "sigma": False,
                    "score": 42,
                },
            ],
        }

        return [
            patch.object(
                JoeSandboxAnalyzer,
                "fetch_existing_results_if_present",
                return_value=analysis_info_response,
            ),
            patch.object(
                JoeSandboxAnalyzer,
                "create_new_analysis",
                return_value="1008",
            ),
            patch.object(
                JoeSandboxAnalyzer,
                "fetch_results",
                return_value=analysis_info_response,
            ),
        ]

    @classmethod
    def get_extra_config(cls) -> dict:
        return {
            "_api_key": "dummy_api_key",
            "url": "https://api.joesandbox.com",
            "force_new_analysis": False,
        }
