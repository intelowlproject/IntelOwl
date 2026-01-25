from unittest.mock import patch

from api_app.analyzers_manager.observable_analyzers.ip2whois import Ip2whois
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)
from tests.mock_utils import MockUpResponse


class Ip2whoisTestCase(BaseAnalyzerTest):
    analyzer_class = Ip2whois

    @staticmethod
    def get_mocked_response():
        mock_response = {
            "domain": "msn.com",
            "domain_id": "4569290_DOMAIN_COM-VRSN",
            "status": "client delete prohibited",
            "create_date": "1994-11-10T05:00:00Z",
            "update_date": "2023-05-03T11:39:17Z",
            "expire_date": "2024-06-04T16:44:29Z",
            "domain_age": 10766,
            "whois_server": "",
            "registrar": {"iana_id": "292", "name": "MarkMonitor Inc.", "url": ""},
            "nameservers": [
                "dns1.p09.nsone.net",
                "ns1-204.azure-dns.com",
                "ns2-204.azure-dns.net",
                "ns3-204.azure-dns.org",
                "ns4-204.azure-dns.info",
            ],
        }
        return patch("requests.get", return_value=MockUpResponse(mock_response, 200))

    @classmethod
    def get_extra_config(cls) -> dict:
        return {"_api_key_name": "dummy_api_key"}
