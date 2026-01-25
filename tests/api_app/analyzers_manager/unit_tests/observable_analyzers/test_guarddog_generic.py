import subprocess
from unittest.mock import patch

from api_app.analyzers_manager.observable_analyzers.guarddog_generic import (
    GuardDogGeneric,
)
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)
from tests.mock_utils import if_mock_connections


class GuardDogGenericTestCase(BaseAnalyzerTest):
    analyzer_class = GuardDogGeneric

    @staticmethod
    def get_mocked_response():
        # Fake response that guarddog CLI would return
        response_from_command = subprocess.CompletedProcess(
            args=["guarddog", "pypi", "scan", "requests", "--output-format=json"],
            returncode=0,
            stdout='{"package": "requests", "issues": 0, "errors": {}, "results": {}, "path": "tmp/T/tmpuoxvqnbr/requests"}',
            stderr="",
        )

        patches = [
            if_mock_connections(
                patch("subprocess.run", return_value=response_from_command)
            )
        ]

        return patches

    @classmethod
    def get_extra_config(cls) -> dict:
        return {"scan_type": "pypi"}
