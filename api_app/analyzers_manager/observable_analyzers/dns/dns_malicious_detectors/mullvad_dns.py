# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.


import base64
import logging
from urllib.parse import urlparse

import dns.message
import httpx

from api_app.analyzers_manager.classes import ObservableAnalyzer
from api_app.analyzers_manager.exceptions import AnalyzerConfigurationException
from api_app.analyzers_manager.observable_analyzers.dns.dns_responses import (
    malicious_detector_response,
)
from api_app.choices import Classification
from tests.mock_utils import MockUpResponse, if_mock_connections, patch

logger = logging.getLogger(__name__)


class MullvadDNSAnalyzer(ObservableAnalyzer):
    """
    MullvadDNSAnalyzer:

    This analyzer queries Mullvad's DNS-over-HTTPS service (using the "base" endpoint)
    to check a domain's DNS records. It supports two modes:
      - "query": returns raw DNS answer data.
      - "malicious": interprets an NXDOMAIN (rcode==3) as the domain being blocked (i.e., malicious).
    """

    url = "https://base.dns.mullvad.net/dns-query"

    def update(self):
        pass

    @staticmethod
    def encode_query(observable: str) -> str:
        """
        Constructs a DNS query for the given observable (domain) for an A record,
        converts it to wire format, and encodes it in URL-safe base64.
        """
        logger.info(f"Encoding DNS query for {observable}")
        query = dns.message.make_query(observable, dns.rdatatype.A)
        wire_query = query.to_wire()
        encoded_query = (
            base64.urlsafe_b64encode(wire_query).rstrip(b"=").decode("ascii")
        )
        logger.info(f"Encoded query: {encoded_query}")
        return encoded_query

    def run(self):
        """
        Executes the analyzer:
          - Validates the observable type (DOMAIN or URL).
          - For URLs, extracts the hostname.
          - Encodes a DNS "A" record query.
          - Makes an HTTP GET request to the Mullvad DoH endpoint.
          - Parses the DNS response.
          - Depending on the configured mode ("query" or "malicious"), returns either raw data or a flagged result.
        """

        if self.observable_classification == Classification.URL:
            logger.info(f"Extracting hostname from URL {self.observable_name}")
            hostname = urlparse(self.observable_name).hostname
            self.observable_name = hostname

        encoded_query = self.encode_query(self.observable_name)
        complete_url = f"{self.url}?dns={encoded_query}"
        logger.info(f"Requesting Mullvad DNS at: {complete_url}")

        try:
            response = httpx.Client(http2=True).get(
                complete_url,
                headers={"accept": "application/dns-message"},
                timeout=30.0,
            )
            response.raise_for_status()
        except httpx.HTTPError as e:
            logger.error(f"HTTP error: {e}")
            raise AnalyzerConfigurationException(f"Failed to query Mullvad DNS: {e}")

        dns_response = dns.message.from_wire(response.content)

        if self.mode == "malicious":
            if dns_response.rcode() == 3:
                return malicious_detector_response(
                    observable=self.observable_name,
                    malicious=True,
                    note="Domain is blocked by Mullvad DNS content filtering.",
                )
            else:
                return malicious_detector_response(
                    observable=self.observable_name,
                    malicious=False,
                    note="Domain is not blocked by Mullvad DNS content filtering.",
                )

        else:
            answers = dns_response.answer
            data = [str(rrset) for rrset in answers] if answers else []
            return {
                "status": "success",
                "data": data,
                "message": f"DNS query for {self.observable_name} completed successfully.",
            }

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch(
                    "httpx.Client.get",
                    return_value=MockUpResponse(
                        {
                            "status": "success",
                            "data": "example.com. 236 IN A 23.215.0.138",
                            "message": "DNS query for example.com completed successfully.",
                        },
                        200,
                        content=b"pn\x01\x03\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01",
                    ),
                )
            )
        ]
        return super()._monkeypatch(patches=patches)
