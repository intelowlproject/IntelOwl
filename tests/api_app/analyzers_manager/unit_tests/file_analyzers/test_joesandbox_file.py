from unittest.mock import patch

from api_app.analyzers_manager.file_analyzers.joesandbox_file import JoeSandboxFile

from .base_test_class import BaseFileAnalyzerTest


class TestJoeSandboxFile(BaseFileAnalyzerTest):
    analyzer_class = JoeSandboxFile

    def get_extra_config(self):
        # Provide values JoeSandboxFile expects at runtime
        return {
            "url": "https://joesandbox.com/api",
            "_api_key": "fake_api_key",
            "force_new_analysis": False,
            "filename": "sample.exe",
            "md5": "0cbc6611f5540bd0809a388dc95a615b",
            "_job": type(
                "JobMock",
                (),
                {
                    "analyzable": type(
                        "AnalyzableMock", (), {"file": b"sample file bytes"}
                    )(),
                    "TLP": 0,
                },
            )(),
        }

    def get_mocked_response(self):
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
            # Present while Live Interaction is active
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
                JoeSandboxFile,
                "fetch_existing_results_if_present",
                return_value=analysis_info_response,
            ),
            patch.object(JoeSandboxFile, "create_new_analysis", return_value="1008"),
            patch.object(
                JoeSandboxFile, "fetch_results", return_value=analysis_info_response
            ),
        ]
