from unittest.mock import Mock, patch

from api_app.analyzers_manager.observable_analyzers.stratosphere import Stratos
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)


class StratosTestCase(BaseAnalyzerTest):
    analyzer_class = Stratos

    @staticmethod
    def get_mocked_response():
        # Simulated API response with CSV format handled by the new parser
        fake_csv_content = b"ip,score\n8.8.8.8,High\n"

        mock_response = Mock()
        mock_response.content = fake_csv_content
        mock_response.raise_for_status.return_value = None

        patches = [
            patch("requests.get", return_value=mock_response),
        ]
        return patches

    @classmethod
    def get_extra_config(cls) -> dict:
        return {}  # Stratos doesn't need extra config
