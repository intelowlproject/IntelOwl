from unittest.mock import patch

from api_app.analyzers_manager.observable_analyzers.dns.dns_malicious_detectors.dns0_eu_malicious_detector import (
    DNS0EUMaliciousDetector,
)
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)
from tests.mock_utils import MockUpResponse


class DNS0EUMaliciousDetectorTestCase(BaseAnalyzerTest):

    analyzer_class = DNS0EUMaliciousDetector

    @staticmethod
    def get_mocked_response():
        return patch(
            "requests.get",
            return_value=MockUpResponse(
                {"Answer": [{"data": "negative-caching.dns0.eu"}]}, 200
            ),
        )
