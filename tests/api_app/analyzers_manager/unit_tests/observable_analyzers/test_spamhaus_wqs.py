from unittest.mock import patch

from api_app.analyzers_manager.observable_analyzers.dns.dns_malicious_detectors.spamhaus_wqs import (
    SpamhausWQS,
)
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)
from tests.mock_utils import MockUpResponse


class SpamhausWQSTestCase(BaseAnalyzerTest):
    analyzer_class = SpamhausWQS

    @staticmethod
    def get_mocked_response():
        def mock_get(url, headers):
            if "example.com" in url:
                # simulate a positive detection
                return MockUpResponse({}, 200)
            else:
                # simulate a clean response
                return MockUpResponse({}, 404)

        return [
            patch("requests.get", side_effect=mock_get),
        ]

    @classmethod
    def get_extra_config(cls):
        return {"_api_key": "dummy-spamhaus-key"}
