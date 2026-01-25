from unittest.mock import patch

from api_app.analyzers_manager.observable_analyzers.criminalip.criminalip import (
    CriminalIp,
)
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)
from tests.mock_utils import MockUpResponse


class CriminalIpTestCase(BaseAnalyzerTest):
    analyzer_class = CriminalIp

    @staticmethod
    def get_mocked_response():
        # Responses based on observable_classification: IP, DOMAIN, GENERIC
        ip_response = {"status": 200, "data": {"verdict": "malicious"}}
        domain_response = {"status": 200, "data": {"hash": "xyz123"}}
        generic_response = {"status": 200, "data": {"banners": ["nginx", "apache"]}}

        return [
            patch(
                "requests.get",
                side_effect=[
                    # for IP observable
                    MockUpResponse(ip_response, 200),
                    # for DOMAIN observable
                    MockUpResponse(domain_response, 200),
                    # for GENERIC observable
                    MockUpResponse(generic_response, 200),
                ],
            )
        ]

    @classmethod
    def get_extra_config(cls):
        return {
            "_api_key_name": "Bearer dummykey",
            "url": "https://dummy.criminalip.io",
            "malicious_info": True,
            "privacy_threat": False,
            "is_safe_dns_server": False,
            "suspicious_info": False,
            "banner_search": True,
            "banner_stats": False,
            "hash_view": True,
        }
