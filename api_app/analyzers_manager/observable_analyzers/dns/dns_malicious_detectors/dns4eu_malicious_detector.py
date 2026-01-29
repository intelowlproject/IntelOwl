# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

"""Check if the domains is reported as malicious in DNS4EU database"""

import logging

import dns.message

from ..dns4eu_base import DNS4EUBase
from ..dns_responses import malicious_detector_response

logger = logging.getLogger(__name__)


class DNS4EUMaliciousDetector(DNS4EUBase):
    url = "https://protective.joindns4.eu/dns-query"

    # DNS4EU blocks by returning 0.0.0.0 or specific sinkhole IPs.
    # 51.15.69.11 is a known sinkhole IP used by Whalebone/DNS4EU.
    # Ref: https://badcyber.com/dns4eu-starts-blocking-domains/
    # Ref: https://protective.joindns4.eu/
    SINKHOLE_IPS = {"0.0.0.0", "51.15.69.11"}

    def run(self):
        is_malicious = False
        timeout = False
        observable = self._get_observable_domain()

        logger.info(
            f"Checking malicious status for {observable} via DNS4EU (binary DoH)"
        )

        # Create DNS query for A record
        query = dns.message.make_query(observable, "A")

        response = self._perform_dns_query(query, self.url)

        # Check for sinkhole IPs in the answer section
        for rrset in response.answer:
            for rr in rrset:
                if rr.rdtype == 1 and rr.to_text() in self.SINKHOLE_IPS:  # A record
                    is_malicious = True
                    break
            if is_malicious:
                break

        return malicious_detector_response(self.observable_name, is_malicious, timeout)

    @classmethod
    def update(cls) -> bool:
        return True
