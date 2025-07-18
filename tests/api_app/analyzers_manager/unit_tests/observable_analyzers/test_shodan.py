from unittest.mock import patch

from api_app.analyzers_manager.observable_analyzers.shodan import Shodan
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)
from tests.mock_utils import MockUpResponse


class ShodanTestCase(BaseAnalyzerTest):
    analyzer_class = Shodan

    @staticmethod
    def get_mocked_response():
        # Return different responses based on analysis type using side_effect
        def _mocked_requests_get(url, params=None, **kwargs):
            if "honeyscore" in url:
                return MockUpResponse(0.5, 200)
            else:
                return MockUpResponse(
                    {
                        "ip_str": "8.8.8.8",
                        "ports": [53, 443],
                        "hostnames": ["dns.google"],
                    },
                    200,
                )

        return patch("requests.get", side_effect=_mocked_requests_get)

    @classmethod
    def get_extra_config(cls) -> dict:
        return {
            "_api_key_name": "fake_api_key",
            "shodan_analysis": "search",  # default mode for tests
        }
