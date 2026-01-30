from unittest.mock import mock_open, patch

from api_app.analyzers_manager.observable_analyzers.tor_nodes_danmeuk import (
    TorNodesDanMeUK,
)
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)


class TorNodesDanMeUKTestCase(BaseAnalyzerTest):
    analyzer_class = TorNodesDanMeUK

    @staticmethod
    def get_mocked_response():
        mock_db_content = "100.10.37.131\n100.14.156.183\n8.8.8.8\n100.16.153.149\n"

        return [
            patch(
                "api_app.analyzers_manager.observable_analyzers.tor_nodes_danmeuk.os.path.isfile",
                return_value=True,
            ),
            patch(
                "api_app.analyzers_manager.observable_analyzers.tor_nodes_danmeuk.os.path.exists",
                return_value=True,
            ),
            patch("builtins.open", mock_open(read_data=mock_db_content)),
        ]
