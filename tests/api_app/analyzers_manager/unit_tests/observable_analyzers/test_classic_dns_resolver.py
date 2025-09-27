from unittest.mock import MagicMock, patch

from api_app.analyzers_manager.observable_analyzers.dns.dns_resolvers.classic_dns_resolver import (
    ClassicDNSResolver,
)
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)


class ClassicDNSResolverTestCase(BaseAnalyzerTest):
    analyzer_class = ClassicDNSResolver

    @staticmethod
    def get_mocked_response():
        mock_rdata = MagicMock()
        mock_rdata.to_text.return_value = "93.184.216.34"

        mock_answer = MagicMock()
        mock_answer.rrset.ttl = 300
        mock_answer.qname.to_text.return_value = "example.com."
        mock_answer.rdtype = 1
        mock_answer.__iter__.return_value = [mock_rdata]

        return [
            patch("socket.gethostbyaddr", return_value=("dns.google", ["alias1"], [])),
            patch("dns.resolver.resolve", return_value=mock_answer),
        ]

    @classmethod
    def get_extra_config(cls):
        return {"query_type": "A"}
