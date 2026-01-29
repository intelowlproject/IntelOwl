# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging

import dns.message

from ..dns4eu_base import DNS4EUBase
from ..dns_responses import dns_resolver_response

logger = logging.getLogger(__name__)


class DNS4EUResolver(DNS4EUBase):
    """Resolve a DNS query with DNS4EU"""

    url = "https://unfiltered.joindns4.eu/dns-query"

    def run(self):
        resolutions = []
        timeout = False
        observable = self._get_observable_domain()

        # We use getattr to safely get the parameter 'query_type'
        q_type = getattr(self, "query_type", "A")

        logger.info(f"Querying DNS4EU (binary DoH) for {observable} (type: {q_type})")

        # Create DNS query
        query = dns.message.make_query(observable, q_type)

        response = self._perform_dns_query(query, self.url)

        for rrset in response.answer:
            for rr in rrset:
                element = {
                    "TTL": rrset.ttl,
                    "data": rr.to_text(),
                    "name": rrset.name.to_text(),
                    "type": rr.rdtype,
                }
                resolutions.append(element)

        return dns_resolver_response(self.observable_name, resolutions, timeout)

    @classmethod
    def update(cls) -> bool:
        return True
