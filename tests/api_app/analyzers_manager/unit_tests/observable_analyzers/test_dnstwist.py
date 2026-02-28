from unittest.mock import MagicMock, patch

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

    def test_run_with_ssl_error(self):
        import ssl

        from api_app.analyzers_manager.models import AnalyzerConfig
        from api_app.choices import Classification

        configs = AnalyzerConfig.objects.filter(python_module=self.analyzer_class.python_module)
        if not configs.exists():
            self.skipTest("No AnalyzerConfig found")
        config = configs.first()
        analyzer = self._setup_analyzer(config, Classification.DOMAIN, "example.com")
        analyzer.report = MagicMock()
        analyzer.report.errors = []

        with patch("dnstwist.run", side_effect=ssl.SSLEOFError("EOF occurred in violation of protocol")):
            analyzer.run()
            self.assertTrue(any("EOF occurred in violation of protocol" in e for e in analyzer.report.errors))
            # lgtm [py/incomplete-url-substring-sanitization]
            self.assertTrue(any("example.com" in e for e in analyzer.report.errors))

    def test_run_with_dns_error(self):
        import socket

        from api_app.analyzers_manager.models import AnalyzerConfig
        from api_app.choices import Classification

        configs = AnalyzerConfig.objects.filter(python_module=self.analyzer_class.python_module)
        if not configs.exists():
            self.skipTest("No AnalyzerConfig found")
        config = configs.first()
        analyzer = self._setup_analyzer(config, Classification.DOMAIN, "example.com")
        analyzer.report = MagicMock()
        analyzer.report.errors = []

        with patch("dnstwist.run", side_effect=socket.gaierror(-2, "Name or service not known")):
            analyzer.run()
            self.assertTrue(any("Name or service not known" in e for e in analyzer.report.errors))
            # lgtm [py/incomplete-url-substring-sanitization]
            self.assertTrue(any("example.com" in e for e in analyzer.report.errors))
