from unittest.mock import patch

from api_app.analyzers_manager.observable_analyzers.netlas import Netlas
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)
from tests.mock_utils import MockUpResponse


class NetlasTestCase(BaseAnalyzerTest):
    analyzer_class = Netlas

    @staticmethod
    def get_mocked_response():
        mock_response = {
            "items": [
                {
                    "data": {
                        "@timestamp": "2023-07-06T14:53:32",
                        "ip": {"gte": "8.8.8.0", "lte": "8.8.8.255"},
                        "related_nets": [
                            {
                                "country": "US",
                                "address": "1600 Amphitheatre Parkway",
                                "city": "Mountain View",
                                "range": "8.8.8.0 - 8.8.8.255",
                                "description": "Google LLC",
                            }
                        ],
                        "asn": {
                            "number": ["15169"],
                            "name": "GOOGLE",
                        },
                    }
                }
            ],
            "took": 8,
            "timestamp": 1691652090,
        }

        return patch("requests.get", return_value=MockUpResponse(mock_response, 200))

    @classmethod
    def get_extra_config(cls) -> dict:
        return {
            "_api_key_name": "mock-api-key",
            "headers": {"X-API-Key": "mock-api-key"},
            "parameters": {"q": "ip:8.8.8.8"},
        }
