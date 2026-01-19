from unittest.mock import mock_open, patch

from api_app.analyzers_manager.observable_analyzers.tor import Tor
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)
from tests.mock_utils import MockUpResponse


class TorTestCase(BaseAnalyzerTest):
    analyzer_class = Tor

    @staticmethod
    def get_mocked_response():
        tor_db_content = "93.95.230.253\n1.2.3.4\n8.8.8.8\n"
        file_mock = mock_open(read_data=tor_db_content)

        return [
            patch(
                "requests.get",
                return_value=MockUpResponse(
                    {},
                    200,
                    content=b"""ExitNode D2A4BEE6754A9711EB0FAC47F3059BE6FC0D72C7
Published 2022-08-17 18:11:11
LastStatus 2022-08-18 14:00:00
ExitAddress 93.95.230.253 2022-08-18 14:44:33""",
                ),
            ),
            patch("builtins.open", file_mock),
            patch("os.path.exists", return_value=True),
            patch("os.path.isfile", return_value=True),
        ]

    @classmethod
    def get_extra_config(cls) -> dict:
        return {}
