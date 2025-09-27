from unittest.mock import patch

from api_app.analyzers_manager.observable_analyzers.auth0 import Auth0
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)


class Auth0AnalyzerTestCase(BaseAnalyzerTest):
    analyzer_class = Auth0

    @staticmethod
    def get_mocked_response():
        # Mock response for Auth0 IP reputation API
        mock_response_data = {
            "ip": "8.8.8.8",
            "classifications": [
                {
                    "name": "clean",
                    "confidence": 0.95,
                    "last_seen": "2024-01-15T10:30:00Z",
                }
            ],
            "risk_score": 0.1,
            "geo": {
                "country": "US",
                "country_name": "United States",
                "region": "CA",
                "city": "Mountain View",
                "latitude": 37.4056,
                "longitude": -122.0775,
            },
            "asn": {"number": 15169, "name": "Google LLC"},
            "threat_intel": {
                "is_malicious": False,
                "categories": [],
                "confidence": 0.95,
            },
            "metadata": {
                "last_updated": "2024-01-15T10:30:00Z",
                "source": "auth0_signals",
            },
        }

        return patch(
            "requests.get",
            return_value=type(
                "MockResponse",
                (),
                {
                    "json": lambda self: mock_response_data,
                    "raise_for_status": lambda self: None,
                    "status_code": 200,
                },
            )(),
        )

    @classmethod
    def get_extra_config(cls) -> dict:
        return {
            "_api_key_name": "dummy_auth0_api_key",
        }
