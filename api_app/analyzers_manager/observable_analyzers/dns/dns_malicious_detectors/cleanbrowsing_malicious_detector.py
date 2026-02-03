# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

"""Check if the domain is reported as malicious in CleanBrowsing database"""

from urllib.parse import urlparse

import dns.message
import dns.rdatatype
import requests

from api_app.analyzers_manager import classes
from api_app.choices import Classification

from ..dns_responses import malicious_detector_response


class CleanBrowsingMaliciousDetector(classes.ObservableAnalyzer):
    """Resolve a DNS query with CleanBrowsing security endpoint,
    Blocked domains return NXDOMAIN with SOA from cleanbrowsing.rpz.noc.org.
    """

    url = "https://doh.cleanbrowsing.org/doh/security-filter/"

    def run(self):
        is_malicious = False
        observable = self.observable_name
        # for URLs we are checking the relative domain
        if self.observable_classification == Classification.URL:
            observable = urlparse(self.observable_name).hostname

        query = dns.message.make_query(observable, dns.rdatatype.A)
        query_wire = query.to_wire()

        response = requests.post(
            self.url,
            data=query_wire,
            headers={
                "Content-Type": "application/dns-message",
                "Accept": "application/dns-message",
            },
            timeout=10,
        )

        dns_response = dns.message.from_wire(response.content)

        # Blocked domains return NXDOMAIN with SOA from cleanbrowsing.rpz.noc.org.
        # ;; AUTHORITY SECTION:
        # malicious.com.		3600	IN	SOA	cleanbrowsing.rpz.noc.org. accesspolicy.rpz.noc.org. 1 7200 900 1209600 86400
        if dns_response.authority:
            for rrset in dns_response.authority:
                for rdata in rrset:
                    if hasattr(rdata, "mname") and str(rdata.mname) == "cleanbrowsing.rpz.noc.org.":
                        is_malicious = True
                        break
                if is_malicious:
                    break

        return malicious_detector_response(self.observable_name, is_malicious)

    @classmethod
    def update(cls) -> bool:
        return True
