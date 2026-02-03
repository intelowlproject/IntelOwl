# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from unittest.mock import patch

import dns.message
import dns.rdataclass
import dns.rdatatype
import dns.rrset

from api_app.analyzers_manager.observable_analyzers.dns.dns_malicious_detectors.dns4eu_malicious_detector import (
    DNS4EUMaliciousDetector,
)
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)


class DNS4EUMaliciousDetectorTestCase(BaseAnalyzerTest):
    analyzer_class = DNS4EUMaliciousDetector

    @staticmethod
    def get_mocked_response():
        # Create a mock DNS message with sinkhole IP (0.0.0.0)
        mock_msg = dns.message.make_response(dns.message.make_query("malicious.com", "A"))
        rrset = dns.rrset.from_text("malicious.com.", 300, dns.rdataclass.IN, dns.rdatatype.A, "0.0.0.0")
        mock_msg.answer.append(rrset)

        return patch("dns.query.https", return_value=mock_msg)
