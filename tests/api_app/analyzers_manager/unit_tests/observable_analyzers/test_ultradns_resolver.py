from unittest.mock import MagicMock, patch

from api_app.analyzers_manager.observable_analyzers.dns.dns_resolvers.ultradns_dns_resolver import (
    UltraDNSDNSResolver,
)
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)


class UltraDNSDNSResolverTestCase(BaseAnalyzerTest):
    analyzer_class = UltraDNSDNSResolver

    @staticmethod
    def get_mocked_response():
        fake_dns_answer = MagicMock()
        fake_dns_answer.qname.to_text.return_value = "example.com."
        fake_dns_answer.rdtype = 1
        fake_dns_answer.rrset.ttl = 300
        fake_dns_answer.__iter__.return_value = [MagicMock(to_text=lambda: "93.184.216.34")]

        return [
            patch(
                "dns.resolver.Resolver.resolve",
                return_value=fake_dns_answer,
            )
        ]

    @classmethod
    def get_extra_config(cls):
        return {"query_type": "A"}
