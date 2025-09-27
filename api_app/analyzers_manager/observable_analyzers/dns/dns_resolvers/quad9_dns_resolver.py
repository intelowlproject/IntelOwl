# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

"""Quad9 DNS resolutions"""
import logging

import httpx

from api_app.analyzers_manager import classes

from ..dns_responses import dns_resolver_response
from ..doh_mixin import DoHMixin

logger = logging.getLogger(__name__)


class Quad9DNSResolver(DoHMixin, classes.ObservableAnalyzer):
    """Resolve a DNS query with Quad9"""

    url: str = "https://dns.quad9.net/dns-query"

    @classmethod
    def update(cls) -> bool:
        pass

    def run(self):
        observable = self.convert_to_domain(
            self.observable_name, self.observable_classification
        )
        complete_url = self.build_query_url(observable)

        attempt_number = 3
        quad9_response = None
        for attempt in range(attempt_number):
            try:
                quad9_response = httpx.Client(http2=True).get(
                    complete_url, headers=self.headers, timeout=10
                )
            except httpx.ConnectError as exception:
                if attempt == attempt_number - 1:
                    raise exception
            else:
                quad9_response.raise_for_status()

        raw_answers = quad9_response.json().get("Answer", []) or []

        resolutions = []
        for record in raw_answers:
            rtype = record.get("type")
            if rtype in (1, 28):  # A and AAAA
                resolutions.append(record.get("data"))
            elif rtype == 5:  # CNAME
                resolutions.append(f"CNAME: {record.get('data')}")
            else:
                resolutions.append(record.get("data", ""))

        return dns_resolver_response(self.observable_name, resolutions)
