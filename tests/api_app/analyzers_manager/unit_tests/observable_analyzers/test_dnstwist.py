from unittest.mock import patch

from api_app.analyzers_manager.observable_analyzers.dnstwist import DNStwist
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)


class DNStwistTestCase(BaseAnalyzerTest):
    analyzer_class = DNStwist

    @staticmethod
    def get_mocked_response():
        # Simulate dnstwist.run() returning a list of domain variants
        mock_result = [
            {
                "domain-name": "example.net",
                "dns-a": ["93.184.216.34"],
                "fuzzer": "addition",
            },
            {"domain-name": "examp1e.com", "dns-a": [], "fuzzer": "homoglyph"},
        ]
        return patch("dnstwist.run", return_value=mock_result)

    @classmethod
    def get_extra_config(cls) -> dict:
        return {
            "tld_dict": "tld.txt",
            "language_dict": "english.txt",
            "fuzzy_hash": "1234abcd5678efgh",
            "fuzzy_hash_url": "http://example.com",
            "mxcheck": True,
            "user_agent": "IntelOwl-Test",
            "nameservers": "8.8.8.8,8.8.4.4",
        }
