# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from unittest.mock import patch

import dns.message
import dns.rdataclass
import dns.rdatatype
import dns.rrset

from api_app.analyzers_manager.observable_analyzers.dns.dns_resolvers.dns4eu_resolver import (
    DNS4EUResolver,
)
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)


class DNS4EUResolverTestCase(BaseAnalyzerTest):
    analyzer_class = DNS4EUResolver

    @staticmethod
    def get_mocked_response():
        # Create a mock DNS message
        mock_msg = dns.message.make_response(dns.message.make_query("example.com", "A"))
        # Add an answer
        rrset = dns.rrset.from_text(
            "example.com.", 300, dns.rdataclass.IN, dns.rdatatype.A, "93.184.216.34"
        )
        mock_msg.answer.append(rrset)

        return patch("dns.query.https", return_value=mock_msg)

    @classmethod
    def get_extra_config(cls):
        return {"query_type": "A"}
