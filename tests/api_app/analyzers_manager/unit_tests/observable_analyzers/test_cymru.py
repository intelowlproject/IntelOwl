from unittest.mock import patch

from api_app.analyzers_manager.observable_analyzers.cymru import Cymru
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)


class CymruTestCase(BaseAnalyzerTest):
    analyzer_class = Cymru

    @staticmethod
    def get_mocked_response():
        mock_response = ("example.com", [], ["192.0.2.1"])
        return patch(
            "socket.gethostbyaddr",
            return_value=mock_response,
        )
