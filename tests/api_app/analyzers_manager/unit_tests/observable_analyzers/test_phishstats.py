from unittest.mock import patch

from api_app.analyzers_manager.observable_analyzers.phishstats import PhishStats
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)
from tests.mock_utils import MockUpResponse


class PhishStatsTestCase(BaseAnalyzerTest):
    analyzer_class = PhishStats

    @staticmethod
    def get_mocked_response():
        mock_json_response = [
            {
                "id": 12345,
                "url": "http://example.com/phish",
                "ip": "8.8.8.8",
                "asn": "AS15169",
                "countrycode": "US",
                "countryname": "United States",
                "date": "2024-01-01",
                "title": "Fake Login Page",
            }
        ]
        return patch(
            "requests.get",
            return_value=MockUpResponse(mock_json_response, 200),
        )
