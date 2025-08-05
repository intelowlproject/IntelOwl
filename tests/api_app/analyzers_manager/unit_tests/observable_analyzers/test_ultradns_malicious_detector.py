from unittest.mock import MagicMock, patch

from api_app.analyzers_manager.observable_analyzers.dns.dns_malicious_detectors.ultradns_malicious_detector import (
    UltraDNSMaliciousDetector,
)
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)


class UltraDNSMaliciousDetectorTestCase(BaseAnalyzerTest):
    analyzer_class = UltraDNSMaliciousDetector

    @staticmethod
    def get_mocked_response():
        # Mock a clean IP (not in sinkhole range)
        mock_rdata_clean = MagicMock()
        mock_rdata_clean.to_text.return_value = "93.184.216.34"  # Not in sinkhole

        return [patch("dns.resolver.Resolver.resolve", return_value=[mock_rdata_clean])]
