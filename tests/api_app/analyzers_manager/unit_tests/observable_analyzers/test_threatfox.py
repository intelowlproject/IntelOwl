from unittest.mock import patch

from api_app.analyzers_manager.observable_analyzers.threatfox import ThreatFox
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)
from tests.mock_utils import MockUpResponse


class ThreatFoxTestCase(BaseAnalyzerTest):
    analyzer_class = ThreatFox

    @staticmethod
    def get_mocked_response():
        mock_response = {
            "query_status": "ok",
            "data": [
                {
                    "id": "12",
                    "ioc": "139.180.203.104:443",
                }
            ],
        }

        return patch(
            "requests.post",
            return_value=MockUpResponse(mock_response, 200),
        )
