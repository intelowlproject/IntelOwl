from unittest.mock import patch

from api_app.analyzers_manager.file_analyzers.guarddog_file import GuardDogFile

from .base_test_class import BaseFileAnalyzerTest


class TestGuardDogFile(BaseFileAnalyzerTest):
    analyzer_class = GuardDogFile

    def get_extra_config(self):
        # Provide values GuardDogFile expects at runtime
        return {
            "scan_type": "pypi",
            "is_requirements_file": True,
        }

    def get_mocked_response(self):
        # Mock subprocess.run to simulate GuardDog output
        return [
            patch(
                "subprocess.run",
                return_value=type(
                    "CompletedProcessMock",
                    (),
                    {
                        "stdout": '[{"dependency": "requests", "ver": "2.32", '
                        '"result": {"iss": 0, "err": {}, "res": {}, '
                        '"path": "/tmp/requests"}}]',
                        "stderr": "INFO: Scanning using at most 8 parallel worker threads\n\n",
                        "returncode": 0,
                    },
                )(),
            )
        ]
