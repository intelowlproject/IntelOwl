# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

"""UltraDNS resolver implementation"""

import logging
from urllib.parse import urlparse

import dns.resolver

from api_app.analyzers_manager import classes
from api_app.choices import Classification

from ..dns_responses import dns_resolver_response

logger = logging.getLogger(__name__)


class UltraDNSDNSResolver(classes.ObservableAnalyzer):
    """Resolve a DNS query with UltraDNS servers"""

    query_type: str

    def update(self) -> bool:
        pass

    def run(self):
        resolutions = []
        observable = self.observable_name
        if self.observable_classification == Classification.URL:
            observable = urlparse(self.observable_name).hostname
        resolver = dns.resolver.Resolver()

        # Configure UltraDNS servers
        resolver.nameservers = ["64.6.64.6", "64.6.65.6"]
        resolver.timeout = 10
        resolver.lifetime = 20

        try:
            dns_resolutions = resolver.resolve(observable, self.query_type)
            for resolution in dns_resolutions:
                element = {
                    "TTL": dns_resolutions.rrset.ttl,
                    "data": resolution.to_text(),
                    "name": dns_resolutions.qname.to_text(),
                    "type": dns_resolutions.rdtype,
                }
                resolutions.append(element)
        except (
            dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
            dns.resolver.NoNameservers,
        ):
            logger.info(f"No resolution for {self.observable_classification} {self.observable_name}")

        return dns_resolver_response(self.observable_name, resolutions)
