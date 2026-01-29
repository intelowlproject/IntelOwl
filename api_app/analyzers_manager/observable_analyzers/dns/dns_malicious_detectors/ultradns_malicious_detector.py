import ipaddress
from urllib.parse import urlparse

import dns.resolver

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from api_app.choices import Classification

from ..dns_responses import malicious_detector_response


class UltraDNSMaliciousDetector(classes.ObservableAnalyzer):
    """Resolve a DNS query with UltraDNS servers,
    if the response falls within the sinkhole range, the domain is malicious.
    """

    def update(self) -> bool:
        pass

    def run(self):
        is_malicious = False
        observable = self.observable_name

        # for URLs we are checking the relative domain
        if self.observable_classification == Classification.URL:
            observable = urlparse(self.observable_name).hostname

        # Configure resolver with both nameservers
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ["156.154.70.2", "156.154.71.2"]
        resolver.timeout = 10  # Time per server
        resolver.lifetime = 20  # Total time for all attempts

        sinkhole_range = ipaddress.ip_network("156.154.112.0/23")

        try:
            answers = resolver.resolve(observable, "A")
            for rdata in answers:
                resolution = rdata.to_text()
                # Check if the resolution falls in the sinkhole range
                if ipaddress.ip_address(resolution) in sinkhole_range:
                    is_malicious = True
                    break

        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            is_malicious = False
        except dns.exception.Timeout:
            raise AnalyzerRunException(
                "Connection to UltraDNS failed - both servers timed out"
            )
        except Exception as e:
            raise AnalyzerRunException(f"DNS query failed: {e}")

        return malicious_detector_response(self.observable_name, is_malicious)
