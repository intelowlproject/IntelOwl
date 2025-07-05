from unittest.mock import patch

from api_app.analyzers_manager.observable_analyzers.ipquery import IPQuery
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)
from tests.mock_utils import MockUpResponse


class IPQueryTestCase(BaseAnalyzerTest):
    analyzer_class = IPQuery

    @staticmethod
    def get_mocked_response():
        mock_response = {
            "ip": "1.1.1.1",
            "isp": {
                "asn": "AS13335",
                "isp": "Cloudflare, Inc.",
                "org": "Cloudflare, Inc.",
            },
            "risk": {
                "is_tor": "false",
                "is_vpn": "false",
                "is_proxy": "false",
                "is_mobile": "false",
                "risk_score": 0,
                "is_datacenter": "true",
            },
            "location": {
                "city": "Sydney",
                "state": "New South Wales",
                "country": "Australia",
                "zipcode": "1001",
                "latitude": -33.854548400186665,
                "timezone": "Australia/Sydney",
                "localtime": "2025-02-03T13:06:16",
                "longitude": 151.20016200912815,
                "country_code": "AU",
            },
        }
        return patch("requests.get", return_value=MockUpResponse(mock_response, 200))
