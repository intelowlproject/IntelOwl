from api_app.analyzers_manager.observable_analyzers.dns.dns_malicious_detectors.dns0_eu_malicious_detector import (
    DNS0EUMaliciousDetector,
)
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)

# from tests.mock_utils import MockUpResponse, if_mock_connections


class DNS0EUMaliciousDetectorTestCase(BaseAnalyzerTest):

    analyzer_class = DNS0EUMaliciousDetector
    mock_patch_key = "dns0_eu"
