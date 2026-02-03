from unittest.mock import patch

from api_app.analyzers_manager.observable_analyzers.crt_sh import Crt_sh
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)
from tests.mock_utils import MockUpResponse


class CrtShTestCase(BaseAnalyzerTest):
    analyzer_class = Crt_sh

    @staticmethod
    def get_mocked_response():
        # Mock SSL certificate data from crt.sh
        mock_certificates = [
            {
                "issuer_ca_id": 16418,
                "issuer_name": "C=US, O=Let's Encrypt, CN=Let's Encrypt Authority X3",
                "name_value": "example.com",
                "min_cert_id": 325717795,
                "min_entry_timestamp": "2024-01-15T16:47:39.089",
                "not_before": "2024-01-15T15:47:39",
                "not_after": "2024-04-15T15:47:39",
            },
            {
                "issuer_ca_id": 7394,
                "issuer_name": "C=US, O=DigiCert Inc, CN=DigiCert SHA2 Secure Server CA",
                "name_value": "www.example.com",
                "min_cert_id": 425717896,
                "min_entry_timestamp": "2024-02-01T10:30:15.234",
                "not_before": "2024-02-01T09:30:15",
                "not_after": "2024-05-01T09:30:15",
            },
            {
                "issuer_ca_id": 12345,
                "issuer_name": "C=US, O=Cloudflare Inc, CN=Cloudflare Origin SSL Certificate",
                "name_value": "*.example.com",
                "min_cert_id": 525717997,
                "min_entry_timestamp": "2023-12-20T08:15:42.567",
                "not_before": "2023-12-20T07:15:42",
                "not_after": "2024-12-20T07:15:42",
            },
        ]

        return [patch("requests.get", return_value=MockUpResponse(mock_certificates, 200))]

    @classmethod
    def get_extra_config(cls) -> dict:
        return {}
