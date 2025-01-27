import base64
import logging
from typing import List
from urllib.parse import urlparse

import dns.message
import requests
from dns.rrset import RRset

from api_app.analyzers_manager import classes
from api_app.choices import Classification

from ..dns_responses import malicious_detector_response

logger = logging.getLogger(__name__)


class AdGuard(classes.ObservableAnalyzer):
    """Check if a domain is malicious by AdGuard public resolver."""

    url = "https://dns.adguard-dns.com/dns-query"

    def update(self) -> bool:
        pass

    # We make DOH(DNS over http) query out of the observable
    # Mainly done using the wire format of the query
    # ref: https://datatracker.ietf.org/doc/html/rfc8484
    @staticmethod
    def encode_query(observable: str) -> str:
        logger.info(f"Encoding query for {observable}")
        query = dns.message.make_query(observable, "A")
        wire_query = query.to_wire()
        encoded_query = (
            base64.urlsafe_b64encode(wire_query).rstrip(b"=").decode("ascii")
        )
        logger.info(f"Encoded query: {encoded_query}")
        return encoded_query

    def filter_query(self, encoded_query: str) -> List[RRset]:
        logger.info(
            f"Sending filtered request to AdGuard DNS API for query: {encoded_query}"
        )
        r_filtered = requests.get(
            url=f"{self.url}?dns={encoded_query}",
            headers={"accept": "application/dns-message"},
        )
        logger.info(f"Received r_filtered from AdGuard DNS API: {r_filtered.content}")
        r_filtered.raise_for_status()
        return dns.message.from_wire(r_filtered.content).answer

    @staticmethod
    def check_a(observable: str, a_filtered: List[RRset]) -> dict:
        # adguard follows 2 patterns for malicious domains,
        # it either redirects the request to ad-block.dns.adguard.com
        # or it sinkholes the request (to 0.0.0.0).
        # If the response contains neither of these,
        # we can safely say the domain is not malicious
        for ans in a_filtered:
            if str(ans.name) == "ad-block.dns.adguard.com.":
                return malicious_detector_response(
                    observable=observable, malicious=True
                )

            if any(str(data) == "0.0.0.0" for data in ans):  # nosec B104
                return malicious_detector_response(
                    observable=observable, malicious=True
                )

        return malicious_detector_response(observable=observable, malicious=False)

    def run(self):
        logger.info(f"Running AdGuard DNS analyzer for {self.observable_name}")
        observable = self.observable_name
        # for URLs we are checking the relative domain
        if self.observable_classification == Classification.URL:
            logger.info(f"Extracting domain from URL {observable}")
            observable = urlparse(self.observable_name).hostname
        encoded_query = self.encode_query(observable)
        a_filtered = self.filter_query(encoded_query)

        if not a_filtered:
            # dont need to check unfiltered if filtered is empty
            # as filter responds even if the domain is not malicious
            # and recognised by adguard
            logger.info(f"Filtered response is empty for {self.observable_name}")
            return malicious_detector_response(
                observable=observable,
                malicious=False,
                note="No response from AdGuard DNS API",
            )

        return self.check_a(observable, a_filtered)
