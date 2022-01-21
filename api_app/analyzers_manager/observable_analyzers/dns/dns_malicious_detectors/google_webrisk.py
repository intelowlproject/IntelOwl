# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

"""Check if the domains is reported as malicious by WebRisk Cloud API"""
import logging
from os.path import exists

from google.cloud.webrisk_v1.services.web_risk_service import WebRiskServiceClient
from google.cloud.webrisk_v1.types import ThreatType

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.observable_analyzers.dns.dns_responses import (
    malicious_detector_response,
)
from api_app.exceptions import AnalyzerRunException
from tests.mock_utils import if_mock_connections, patch

logger = logging.getLogger(__name__)


class WebRisk(classes.ObservableAnalyzer):
    """Check if observable analyzed is marked as malicious by Google WebRisk API"""

    def run(self):
        credentials = self._secrets["api_key_name"]
        if not exists(credentials):
            raise AnalyzerRunException(
                f"{credentials} should be an existing file. "
                "Check the docs on how to add this file to"
                " properly execute this analyzer"
            )

        web_risk_client = WebRiskServiceClient()
        # threat types
        # MALWARE = 1
        # SOCIAL_ENGINEERING = 2
        # THREAT_TYPE_UNSPECIFIED = 0 should not be used
        # UNWANTED_SOFTWARE = 3
        threat_types = [ThreatType(1), ThreatType(2), ThreatType(3)]
        response = web_risk_client.search_uris(
            uri=self.observable_name, threat_types=threat_types, timeout=5
        )
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

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch(
                    "api_app.analyzers_manager.observable_analyzers.dns."
                    "dns_malicious_detectors.google_webrisk.WebRiskServiceClient"
                )
            )
        ]
        return super()._monkeypatch(patches=patches)
