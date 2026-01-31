from unittest.mock import MagicMock, patch

from api_app.analyzers_manager.observable_analyzers.dns.dns_malicious_detectors.google_webrisk import (
    WebRisk,
)
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)


class WebRiskAnalyzerTestCase(BaseAnalyzerTest):
    analyzer_class = WebRisk

    @staticmethod
    def get_mocked_response():
        mock_credentials = MagicMock()
        mock_webrisk_client = MagicMock()

        # Simulate threat types returned by WebRisk
        threat_response = MagicMock()
        threat_response.threat.threat_types = [1, 2]  # MALWARE and SOCIAL_ENGINEERING

        PATCH_PATH = (
            "api_app.analyzers_manager.observable_analyzers.dns."
            "dns_malicious_detectors.google_webrisk.service_account."
            "Credentials.from_service_account_info"
        )

        # Patch credentials and API call
        return [
            patch(
                PATCH_PATH,
                return_value=mock_credentials,
            ),
            patch(
                "api_app.analyzers_manager.observable_analyzers.dns.dns_malicious_detectors.google_webrisk.WebRiskServiceClient",
                return_value=mock_webrisk_client,
            ),
            patch.object(mock_webrisk_client, "search_uris", return_value=threat_response),
        ]

    @classmethod
    def get_extra_config(cls):
        return {
            "_service_account_json": {
                "type": "service_account",
                "project_id": "demo-project",
                "private_key_id": "some_key_id",
                "private_key": "-----BEGIN PRIVATE KEY-----\\nABC...\\n-----END PRIVATE KEY-----\\n",
                "client_email": "demo@demo.iam.gserviceaccount.com",
                "client_id": "1234567890",
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
                "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/demo",
            }
        }
