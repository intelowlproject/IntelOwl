import base64
import logging
from typing import List
from urllib.parse import urlparse

import dns.message
import requests
from dns.rrset import RRset

from api_app.analyzers_manager import classes

from ..dns_responses import malicious_detector_response

logger = logging.getLogger(__name__)


class AdGuard(classes.ObservableAnalyzer):
    """Check if a domain is malicious by AdGuard public resolver."""

    headers = {"accept": "application/dns-message"}
    url = "https://dns.adguard-dns.com/"  # for health chack

    url_no_filter = "https://unfiltered.adguard-dns.com/dns-query"

    # malicious dns -> contains ans
    # non-malicious dns -> empty ans
    url_dns_filter = "https://dns.adguard-dns.com/dns-query"

    def update(self) -> bool:
        pass

    # We make DOH(DNS over http) query out of the observable
    # Mainly done using the wire format of the query
    # ref: https://datatracker.ietf.org/doc/html/rfc8484
    def encode_query(self, observable: str) -> str:
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
            url=f"{self.url_dns_filter}?dns={encoded_query}",
            headers=self.headers,
        )
        logger.info(f"Received r_filtered from AdGuard DNS API: {r_filtered.content}")
        r_filtered.raise_for_status()
        return dns.message.from_wire(r_filtered.content).answer

    def unfiltered_query(self, encoded_query: str) -> List[RRset]:
        logger.info(
            f"Sending unfiltered request to AdGuard DNS API for query: {encoded_query}"
        )
        r_unfiltered = requests.get(
            url=f"{self.url_no_filter}?dns={encoded_query}",
            headers=self.headers,
        )
        logger.info(
            f"Received r_unfiltered from AdGuard DNS API: {r_unfiltered.content}"
        )
        r_unfiltered.raise_for_status()
        return dns.message.from_wire(r_unfiltered.content).answer

    def run(self):
        logger.info(f"Running AdGuard DNS analyzer for {self.observable_name}")
        observable = self.observable_name
        # for URLs we are checking the relative domain
        if self.observable_classification == self.ObservableTypes.URL:
            logger.info(f"Extracting domain from URL {observable}")
            observable = urlparse(self.observable_name).hostname
        encoded_query = self.encode_query(observable)
        a_filtered = self.filter_query(encoded_query)
        #         "answers": [
        #     {
        #       "name": "crambidnonutilitybayadeer.com.",
        #       "type": "CNAME",
        #       "ttl": 3600,
        #       "data": "ad-block.dns.adguard.com."
        #     },
        #     {
        #       "name": "ad-block.dns.adguard.com.",
        #       "type": "A",
        #       "ttl": 742,
        #       "data": "94.140.14.36"
        #     }
        #   ],

        if not a_filtered:
            logger.info(f"Filtered response is empty for {self.observable_name}")
            a_unfiltered = self.unfiltered_query(encoded_query)
            if not a_unfiltered:
                # If both responses are empty,
                # we can't determine if the domain is malicious
                # as it might still be a valid domain
                # but not recognised by AdGuard at all
                logger.info(f"Unfiltered response is empty for {self.observable_name}")
                return malicious_detector_response(
                    observable=observable,
                    malicious=False,
                    note="Not recognised by AdGuard at all.",
                )

        # adguard follows 2 patterns for malicious domains
        # it either redirects the request to ad-block.dns.adguard.com
        # or it sinkholes the request (to 0.0.0.0).
        # If the response contains neither of these,
        for ans in a_filtered:
            if ans.name == "ad-block.dns.adguard.com.":
                # means being redirected to ad guard alert page
                return malicious_detector_response(
                    observable=observable, malicious=True
                )
            for data in ans:
                if data == "0.0.0.0":
                    # means sinkhole
                    return malicious_detector_response(
                        observable=observable, malicious=True
                    )
        return False
