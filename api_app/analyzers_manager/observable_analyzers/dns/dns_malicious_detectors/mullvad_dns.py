# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.


import logging

import dns.message
import httpx

from api_app.analyzers_manager.classes import ObservableAnalyzer
from api_app.analyzers_manager.exceptions import AnalyzerConfigurationException
from api_app.analyzers_manager.observable_analyzers.dns.dns_responses import (
    malicious_detector_response,
)
from api_app.analyzers_manager.observable_analyzers.dns.doh_mixin import DoHMixin

logger = logging.getLogger(__name__)


class MullvadDNSAnalyzer(DoHMixin, ObservableAnalyzer):
    """
    MullvadDNSAnalyzer:

    This analyzer queries Mullvad's DNS-over-HTTPS service (using the "base" endpoint)
    to check a domain's DNS records. It supports two modes:
      - "query": returns raw DNS answer data.
      - "malicious": interprets an NXDOMAIN (rcode==3) as the domain being blocked (i.e., malicious).
    """

    url = "https://base.dns.mullvad.net/dns-query"
    mode: str = "query"

    def update(self):
        pass

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
        observable = self.convert_to_domain(self.observable_name, self.observable_classification)
        complete_url = self.build_query_url(observable)

        try:
            response = httpx.Client(http2=True).get(
                complete_url,
                headers=self.headers,
                timeout=30.0,
            )
            response.raise_for_status()
        except httpx.HTTPError as e:
            logger.error(f"HTTP error: {e}")
            raise AnalyzerConfigurationException(f"Failed to query Mullvad DNS: {e}")

        dns_response = dns.message.from_wire(response.content)

        if self.mode == "malicious":
            malicious = dns_response.rcode() == 3
            return malicious_detector_response(
                observable=observable,
                malicious=malicious,
                note=f"Domain is {'' if malicious else 'not '}blocked by Mullvad DNS content filtering.",
            )

        elif self.mode == "query":
            answers = dns_response.answer
            data = [str(rrset) for rrset in answers] if answers else []
            return {
                "status": "success",
                "data": data,
                "message": f"DNS query for {observable} completed successfully.",
            }
        else:
            raise AnalyzerConfigurationException(
                f"Invalid mode: {self.mode}. Must be 'query' or 'malicious'."
            )
