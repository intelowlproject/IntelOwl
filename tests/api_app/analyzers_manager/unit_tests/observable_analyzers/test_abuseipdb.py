from unittest.mock import patch

from api_app.analyzers_manager.observable_analyzers.abuseipdb import AbuseIPDB
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)


class AbuseIPDBTestCase(BaseAnalyzerTest):
    analyzer_class = AbuseIPDB

    @staticmethod
    def get_mocked_response():
        mock_response = {
            "data": {
                "ipAddress": "8.8.8.8",
                "isPublic": True,
                "isWhitelisted": False,
                "abuseConfidenceScore": 42,
                "countryCode": "US",
                "usageType": "Data Center/Web Hosting/Transit",
                "isp": "Google LLC",
                "domain": "google.com",
                "totalReports": 20,
                "lastReportedAt": "2025-01-01T12:00:00Z",
                "reports": [
                    {
                        "categories": [1, 4, 7],
                        "comment": "Suspicious activity",
                        "reporterId": 123456,
                    },
                    {
                        "categories": [5, 14],
                        "comment": "Brute force detected",
                        "reporterId": 789012,
                    },
                ],
            }
        }

        return patch(
            "requests.get",
            return_value=type(
                "MockResponse",
                (),
                {
                    "json": lambda _: mock_response,
                    "raise_for_status": lambda _: None,
                    "status_code": 200,
                },
            )(),
        )

    @classmethod
    def get_extra_config(cls) -> dict:
        return {
            "_api_key_name": "dummy_api_key",
            "max_age": 90,
            "max_reports": 1,
            "verbose": True,
        }
