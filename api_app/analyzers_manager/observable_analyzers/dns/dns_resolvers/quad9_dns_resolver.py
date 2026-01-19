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

        # sometimes it can respond with 503, I suppose to avoid DoS.
        # In 1k requests just 20 fails and at least with 30 requests between 2 failures
        # with 2 or 3 attemps the analyzer should get the data
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

        json_response = quad9_response.json()
        resolutions: list[str] = []
        for answer in json_response.get("Answer", []):
            if "data" in answer:
                resolutions.append(answer["data"])

        return dns_resolver_response(observable, resolutions)
