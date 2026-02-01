# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

"""Check if the domains is reported as malicious by WebRisk Cloud API"""

import logging

from google.cloud.webrisk_v1.services.web_risk_service import WebRiskServiceClient
from google.cloud.webrisk_v1.types import ThreatType
from google.oauth2 import service_account

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from api_app.analyzers_manager.observable_analyzers.dns.dns_responses import (
    malicious_detector_response,
)
from api_app.choices import Classification

logger = logging.getLogger(__name__)


class WebRisk(classes.ObservableAnalyzer):
    """Check if observable analyzed is marked as malicious by Google WebRisk API

    Get these secrets from a Service Account valid file.
    Example:
        {
          "type": "service_account",
          "project_id": "test",
          "private_key_id": "34543543543534",
          "private_key": "test",
          "client_email": "test@test.iam.gserviceaccount.com",
          "client_id": "363646436363463663634",
          "auth_uri": "https://accounts.google.com/o/oauth2/auth",
          "token_uri": "https://oauth2.googleapis.com/token",
          "auth_provider_x509_cert_url":
           "https://www.googleapis.com/oauth2/v1/certs",
          "client_x509_cert_url":
           "https://www.googleapis.com/robot/v1/metadata/x509/somedomain"
        }
    """

    _service_account_json: dict

    def run(self):
        if self.observable_classification == Classification.URL and not self.observable_name.startswith(
            "http"
        ):
            raise AnalyzerRunException(
                f"{self.observable_name} not supported because it does not start with http"
            )

        credentials = service_account.Credentials.from_service_account_info(self._service_account_json)

        web_risk_client = WebRiskServiceClient(credentials=credentials)
        # threat types
        # MALWARE = 1
        # SOCIAL_ENGINEERING = 2
        # THREAT_TYPE_UNSPECIFIED = 0 should not be used
        # UNWANTED_SOFTWARE = 3
        threat_types = [ThreatType(1), ThreatType(2), ThreatType(3)]
        response = web_risk_client.search_uris(uri=self.observable_name, threat_types=threat_types, timeout=5)
        threats_found = response.threat
        # ThreatUri object
        logger.debug(f"threat founds {threats_found}")

        threat_types = threats_found.threat_types

        malicious = bool(threat_types)
        web_risk_result = malicious_detector_response(self.observable_name, malicious)
        # append extra data
        if malicious:
            threats_list = []
            if 1 in threat_types:
                threats_list.append("MALWARE")
            if 2 in threat_types:
                threats_list.append("SOCIAL_ENGINEERING")
            if 3 in threat_types:
                threats_list.append("UNWANTED_SOFTWARE")
            web_risk_result["threats"] = threats_list
        return web_risk_result
