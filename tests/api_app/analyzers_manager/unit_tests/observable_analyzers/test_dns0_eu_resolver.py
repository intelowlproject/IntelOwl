from unittest.mock import patch

from api_app.analyzers_manager.observable_analyzers.dns.dns_resolvers.dns0_eu_resolver import (
    DNS0EUResolver,
)
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)
from tests.mock_utils import MockUpResponse


class DNS0EUResolverTestCase(BaseAnalyzerTest):
    analyzer_class = DNS0EUResolver

    @staticmethod
    def get_mocked_response():
        mock_response = {
            "Answer": [
                {"name": "example.com.", "type": 1, "TTL": 300, "data": "93.184.216.34"}
            ]
        }

        return [patch("requests.get", return_value=MockUpResponse(mock_response, 200))]

    @classmethod
    def get_extra_config(cls):
        return {"query_type": "A"}
