from unittest.mock import patch

from api_app.analyzers_manager.observable_analyzers.censys import Censys
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)
from tests.mock_utils import MockUpResponse


class CensysTestCase(BaseAnalyzerTest):
    analyzer_class = Censys

    @staticmethod
    def get_mocked_response():
        mock_response = {
            "code": 200,
            "status": "OK",
            "result": {
                "ip": "8.8.8.8",
                "services": [{"port": 53, "service_name": "DNS", "transport_protocol": "UDP"}],
                "location": {
                    "continent": "North America",
                    "country": "United States",
                    "country_code": "US",
                    "city": "Mountain View",
                    "coordinates": {"latitude": 37.4056, "longitude": -122.0775},
                },
                "autonomous_system": {
                    "asn": 15169,
                    "description": "Google LLC",
                    "name": "Google LLC",
                    "country_code": "US",
                },
            },
        }

        return patch(
            "requests.get",
            return_value=MockUpResponse(mock_response, 200),
        )

    @classmethod
    def get_extra_config(cls) -> dict:
        return {
            "censys_analysis": "search",
            "_api_id_name": "test_api_id",
            "_api_secret_name": "test_api_secret",
        }
