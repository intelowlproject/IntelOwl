import ipaddress
from urllib.parse import urlparse

import dns.resolver

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from tests.mock_utils import if_mock_connections, patch

from ..dns_responses import malicious_detector_response


class UltraDNSMaliciousDetector(classes.ObservableAnalyzer):
    """Resolve a DNS query with UltraDNS servers,
    if the response falls within the sinkhole range, the domain is malicious.
    """

    def update(self) -> bool:
        pass

    def run(self):
        try:
            is_malicious = False
            observable = self.observable_name

            # for URLs we are checking the relative domain
            if self.observable_classification == self.ObservableTypes.URL:
                observable = urlparse(self.observable_name).hostname

            primary_dns = "156.154.70.2"
            backup_dns = "156.154.71.2"
            sinkhole_range = ipaddress.ip_network("156.154.112.0/23")

            # Try primary DNS server first
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [primary_dns]

            try:
                answers = resolver.resolve(observable, "A")
                for rdata in answers:
                    resolution = rdata.to_text()
                    # Check if the resolution falls in the sinkhole range
                    if ipaddress.ip_address(resolution) in sinkhole_range:
                        is_malicious = True
                        break
            except dns.exception.Timeout:
                # If primary DNS times out, try backup DNS
                resolver.nameservers = [backup_dns]
                try:
                    answers = resolver.resolve(observable, "A")
                    for rdata in answers:
                        resolution = rdata.to_text()
                        if ipaddress.ip_address(resolution) in sinkhole_range:
                            is_malicious = True
                            break
                except dns.exception.Timeout:
                    raise AnalyzerRunException("Connection to UltraDNS failed")
                except Exception as e:
                    raise Exception(f"DNS query failed for {backup_dns}: {e}")
            except Exception as e:
                raise Exception(f"DNS query failed for {primary_dns}: {e}")

        except Exception as e:
            raise AnalyzerRunException(f"An error occurred: {e}")

        return malicious_detector_response(self.observable_name, is_malicious)

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch("dns.resolver.Resolver.resolve", return_value=["156.154.112.16"]),
            )
        ]
        return super()._monkeypatch(patches=patches)
