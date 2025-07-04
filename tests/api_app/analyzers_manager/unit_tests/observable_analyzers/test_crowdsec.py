from unittest.mock import patch

from api_app.analyzers_manager.observable_analyzers.crowdsec import Crowdsec
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)
from tests.mock_utils import MockUpResponse


class CrowdsecTestCase(BaseAnalyzerTest):
    analyzer_class = Crowdsec

    @staticmethod
    def get_mocked_response():
        # Simple mock response with essential CrowdSec data structure
        mock_response = {
            "classifications": {
                "classifications": [
                    {
                        "name": "crowdsecurity/ssh-bf",
                        "label": "SSH Bruteforce",
                        "description": "SSH bruteforce attack detected",
                    }
                ]
            },
            "behaviors": [
                {
                    "name": "http:exploit",
                    "label": "HTTP Exploit",
                    "description": "HTTP exploitation attempts",
                }
            ],
            "scores": {
                "overall": {
                    "aggressiveness": 3,
                    "threat": 2,
                    "trust": 4,
                    "anomaly": 1,
                    "total": 3,
                }
            },
        }

        return [patch("requests.get", return_value=MockUpResponse(mock_response, 200))]

    @classmethod
    def get_extra_config(cls) -> dict:
        return {"_api_key_name": "test_api_key_12345"}
