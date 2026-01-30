import logging

import dns.message
import requests
from dns.rrset import RRset

from api_app.analyzers_manager import classes

from ..dns_responses import malicious_detector_response
from ..doh_mixin import DoHMixin

logger = logging.getLogger(__name__)


class AdGuard(DoHMixin, classes.ObservableAnalyzer):
    """Check if a domain is malicious by AdGuard public resolver."""

    url: str = "https://dns.adguard-dns.com/dns-query"

    def update(self) -> bool:
        pass

    def filter_query(self, observable: str) -> list[RRset]:
        logger.info(f"Sending filtered request to AdGuard DNS API for query: {observable}")
        r_filtered = requests.get(
            url=self.build_query_url(observable),
            headers=self.headers,
        )
        logger.info(f"Received r_filtered from AdGuard DNS API: {r_filtered.content}")
        r_filtered.raise_for_status()
        return dns.message.from_wire(r_filtered.content).answer

    @staticmethod
    def check_a(observable: str, a_filtered: list[RRset]) -> dict:
        # adguard follows 2 patterns for malicious domains,
        # it either redirects the request to ad-block.dns.adguard.com
        # or it sinkholes the request (to 0.0.0.0).
        # If the response contains neither of these,
        # we can safely say the domain is not malicious
        for ans in a_filtered:
            if str(ans.name) == "ad-block.dns.adguard.com.":
                return malicious_detector_response(observable=observable, malicious=True)

            if any(str(data) == "0.0.0.0" for data in ans):  # nosec B104
                return malicious_detector_response(observable=observable, malicious=True)

        return malicious_detector_response(observable=observable, malicious=False)

    def run(self):
        logger.info(f"Running AdGuard DNS analyzer for {self.observable_name}")
        observable = self.convert_to_domain(self.observable_name, self.observable_classification)
        a_filtered = self.filter_query(observable)

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
