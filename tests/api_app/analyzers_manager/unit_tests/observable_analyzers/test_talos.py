from unittest.mock import mock_open, patch

from api_app.analyzers_manager.observable_analyzers.talos import Talos
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)


class TalosTestCase(BaseAnalyzerTest):
    analyzer_class = Talos

    @staticmethod
    def get_mocked_response():
        # Simulate Talos IP list containing the test IP
        fake_file_content = "91.192.100.61\n8.8.8.8\n1.1.1.1"

        return [
            patch("builtins.open", mock_open(read_data=fake_file_content)),
            patch("os.path.isfile", return_value=True),
            patch("os.path.exists", return_value=True),
        ]

    @classmethod
    def get_extra_config(cls) -> dict:
        return {}  #
