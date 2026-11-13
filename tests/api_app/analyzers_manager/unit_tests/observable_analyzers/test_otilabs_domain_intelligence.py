# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from unittest.mock import patch

from api_app.analyzers_manager.exceptions import AnalyzerRunException
from api_app.analyzers_manager.models import AnalyzerConfig
from api_app.analyzers_manager.observable_analyzers.otilabs_domain_intelligence import (
    OTILabsDomainIntelligence,
)
from api_app.choices import Classification
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)
from tests.mock_utils import MockUpResponse

# trimmed copy of a real /lookup response for example.com (lists shortened)
MOCK_RESPONSE = {
    "domain": "example.com",
    "elapsed_ms": 74,
    "cached": {"dns": False, "ssl": True, "whois": False, "subdomains": True, "email_security": False},
    "dns": {
        "A": ["104.20.23.154", "172.66.147.243"],
        "AAAA": ["2606:4700:10::6814:179a", "2606:4700:10::ac42:93f3"],
        "MX": ["0 ."],
        "TXT": ['"v=spf1 -all"'],
        "NS": ["elliott.ns.cloudflare.com.", "hera.ns.cloudflare.com."],
        "CAA": [],
        "SOA": ["elliott.ns.cloudflare.com. dns.cloudflare.com. 2416374680 10000 2400 604800 1800"],
    },
    "ssl": {
        "issuer": "CN=Cloudflare TLS Issuing ECC CA 3,O=SSL Corporation,C=US",
        "subject": "CN=example.com",
        "valid_from": "2026-09-26T22:49:11+00:00",
        "valid_to": "2026-12-25T22:56:35+00:00",
        "days_until_expiry": 81,
        "serial_number": "2569673129085639595562975411803018896",
        "sans": ["example.com", "*.example.com"],
        "signature_algorithm": "ecdsa-with-SHA256",
    },
    "whois": {
        "registrar": "RESERVED-Internet Assigned Numbers Authority",
        "created": "1995-08-14T04:00:00Z",
        "updated": "2026-08-14T08:01:43Z",
        "expires": "2027-08-13T04:00:00Z",
        "nameservers": ["ELLIOTT.NS.CLOUDFLARE.COM", "HERA.NS.CLOUDFLARE.COM"],
        "status": ["client delete prohibited", "client transfer prohibited"],
        "_source": "rdap.org",
    },
    "subdomains": {
        "count": 18535,
        "live_count": 0,
        "returned": 3,
        "subdomains": ["0000.example.com", "001.example.com", "01.example.com"],
        "live": [],
        "pools": [{"zone": "*.static.example.com", "count": 271}],
        "sources_used": ["certspotter: 2 found", "virustotal: 123 found", "subfinder: 19064 found"],
    },
    "email_security": {
        "spf": {"present": True, "records": ["v=spf1 -all"]},
        "dmarc": {"present": True, "records": ["v=DMARC1;p=reject;sp=reject;adkim=s;aspf=s"]},
        "dkim": {
            "found": ["google"],
            "records": [{"selector": "google", "records": ["v=DKIM1; p="]}],
            "note": (
                "Probed common selectors (Google, Microsoft 365, Mailchimp, SendGrid, etc.). "
                "Custom or hash-based selectors aren't auto-discoverable."
            ),
        },
    },
}


class OTILabsDomainIntelligenceTestCase(BaseAnalyzerTest):
    analyzer_class = OTILabsDomainIntelligence

    @staticmethod
    def get_mocked_response():
        return patch("requests.get", return_value=MockUpResponse(MOCK_RESPONSE, 200))

    @classmethod
    def get_extra_config(cls) -> dict:
        return {"_api_key_name": "dummy_key"}

    def _analyzer(self, classification, value):
        config = AnalyzerConfig.objects.filter(python_module=self.analyzer_class.python_module).first()
        if not config:
            self.skipTest("No AnalyzerConfig found")
        return self._setup_analyzer(config, classification, value)

    def test_url_is_looked_up_by_hostname(self):
        analyzer = self._analyzer(Classification.URL, "https://login.example.com/reset?id=1")
        with patch("requests.get", return_value=MockUpResponse(MOCK_RESPONSE, 200)) as mock_get:
            analyzer.run()
        self.assertEqual(
            mock_get.call_args.args[0],
            "https://domain-intelligence-api.p.rapidapi.com/lookup/login.example.com",
        )
        headers = mock_get.call_args.kwargs["headers"]
        self.assertEqual(headers["X-RapidAPI-Key"], "dummy_key")
        self.assertEqual(headers["X-RapidAPI-Host"], "domain-intelligence-api.p.rapidapi.com")

    def test_rejected_key(self):
        analyzer = self._analyzer(Classification.DOMAIN, "example.com")
        with patch("requests.get", return_value=MockUpResponse({}, 403)):
            with self.assertRaises(AnalyzerRunException):
                analyzer.run()

    def test_quota_reached(self):
        analyzer = self._analyzer(Classification.DOMAIN, "example.com")
        with patch("requests.get", return_value=MockUpResponse({}, 429)):
            with self.assertRaises(AnalyzerRunException):
                analyzer.run()
