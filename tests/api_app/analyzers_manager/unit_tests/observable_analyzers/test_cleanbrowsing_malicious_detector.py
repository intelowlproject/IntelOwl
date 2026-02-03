# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from unittest.mock import MagicMock, patch

import dns.message
import dns.name
import dns.rdataclass
import dns.rdatatype
import dns.rdtypes.ANY.SOA

from api_app.analyzers_manager.observable_analyzers.dns.dns_malicious_detectors.cleanbrowsing_malicious_detector import (
    CleanBrowsingMaliciousDetector,
)
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)


class CleanBrowsingMaliciousDetectorTestCase(BaseAnalyzerTest):
    analyzer_class = CleanBrowsingMaliciousDetector

    @classmethod
    def get_mocked_response(cls):
        mock_msg = dns.message.make_response(dns.message.make_query("malicious.com", "A"))
        mock_msg.set_rcode(dns.rcode.NXDOMAIN)

        soa = dns.rdtypes.ANY.SOA.SOA(
            rdclass=dns.rdataclass.IN,
            rdtype=dns.rdatatype.SOA,
            mname=dns.name.from_text("cleanbrowsing.rpz.noc.org."),
            rname=dns.name.from_text("accesspolicy.cleanbrowsing.rpz.noc.org."),
            serial=1,
            refresh=7200,
            retry=900,
            expire=1209600,
            minimum=86400,
        )

        rrset = dns.rrset.from_rdata("malicious.com.", 3600, soa)
        mock_msg.authority.append(rrset)

        mock_response = MagicMock()
        mock_response.content = mock_msg.to_wire()

        return patch("requests.post", return_value=mock_response)
