from unittest.mock import patch

from api_app.analyzers_manager.observable_analyzers.dns.dns_malicious_detectors.cloudflare_malicious_detector import (
    CloudFlareMaliciousDetector,
)
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)
from tests.mock_utils import MockUpResponse


class CloudFlareMalicioudDetectorTestCase(BaseAnalyzerTest):
    analyzer_class = CloudFlareMaliciousDetector

    @staticmethod
    def get_mocked_response():
        return patch(
            "requests.get",
            return_value=MockUpResponse({"Answer": [{"data": "0.0.0.0"}]}, 200),
        )
