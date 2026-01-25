from unittest.mock import patch

from api_app.analyzers_manager.observable_analyzers.dns.dns_malicious_detectors.dns4eu_malicious_detector import (
    DNS4EUMaliciousDetector,
)
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)
from tests.mock_utils import MockUpResponse


class DNS4EUMaliciousDetectorTestCase(BaseAnalyzerTest):

    analyzer_class = DNS4EUMaliciousDetector

    @staticmethod
    def get_mocked_response():
        # Mocking a malicious response (0.0.0.0)
        return patch(
            "requests.get",
            return_value=MockUpResponse({"Answer": [{"data": "0.0.0.0"}]}, 200),
        )
