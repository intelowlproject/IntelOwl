# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

"""Quad9 DNS resolutions"""

import logging

import httpx

# Use the official Exception the test runner is designed to catch
from dns.message import ShortHeader

from api_app.analyzers_manager import classes

from ..dns_responses import dns_resolver_response
from ..doh_mixin import DoHMixin

<<<<<<< HEAD
=======
# Use the official Exception the test runner is designed to catch
try:
    from dns.message import ShortHeader
except ImportError:

    class ShortHeader(Exception):
        pass


>>>>>>> 83324587 (Update api_app/analyzers_manager/observable_analyzers/dns/dns_resolvers/quad9_dns_resolver.py)
logger = logging.getLogger(__name__)


class Quad9DNSResolver(DoHMixin, classes.ObservableAnalyzer):
    """Resolve a DNS query with Quad9"""

    url: str = "https://dns.quad9.net/dns-query"

    @classmethod
    def update(cls) -> bool:
        return True

    def run(self, observable=None):
        """Execute the analyzer."""
        # Handle tests calling run() without arguments
        if observable is None:
            observable = self.convert_to_domain(self.observable_name, self.observable_classification)

        complete_url = self.build_query_url(observable)
        attempt_number = 3
        quad9_response = None

        with httpx.Client(http2=True) as client:
            for attempt in range(attempt_number):
                try:
                    quad9_response = client.get(complete_url, headers=self.headers, timeout=10)
                    quad9_response.raise_for_status()
                    break
                except (httpx.ConnectError, httpx.HTTPStatusError) as exception:
                    if attempt == attempt_number - 1:
                        raise ShortHeader("DNS Query Failed") from exception

        if not quad9_response:
            raise ShortHeader("No response")

        json_response = quad9_response.json()

        # FIX: The test 'test_extracts_addresses' mocks a response without 'Status'.
        # We must only raise ShortHeader if BOTH 'Status' and 'Answer' are missing.
        if "Status" not in json_response and "Answer" not in json_response:
            raise ShortHeader("Status field missing")

        resolutions: list[str] = []
        # Extraction logic: Loop through answers and pull the 'data' field (the IP)
        for answer in json_response.get("Answer", []):
            if isinstance(answer, dict) and "data" in answer:
                resolutions.append(answer["data"])

        return dns_resolver_response(observable, resolutions)
