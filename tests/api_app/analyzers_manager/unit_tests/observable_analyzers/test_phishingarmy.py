from unittest.mock import mock_open, patch

from api_app.analyzers_manager.observable_analyzers.phishing_army import PhishingArmy
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)
from tests.mock_utils import MockUpResponse


class PhishingArmyTestCase(BaseAnalyzerTest):
    analyzer_class = PhishingArmy

    @staticmethod
    def get_mocked_response():
        mock_db_content = "91.192.100.61\nexample.com"

        return [
            patch(
                "requests.get",
                return_value=MockUpResponse({}, 200, content=mock_db_content.encode()),
            ),
            patch("builtins.open", mock_open(read_data=mock_db_content)),
            patch("os.path.isfile", return_value=True),
            patch("os.path.exists", return_value=True),
        ]
