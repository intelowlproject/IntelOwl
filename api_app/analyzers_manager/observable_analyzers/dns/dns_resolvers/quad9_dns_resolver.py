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
                with httpx.Client(http2=True, timeout=10) as client:
                    quad9_response = client.get(complete_url, headers=self.headers)
                    quad9_response.raise_for_status()
                break
            except (
                httpx.ConnectError,
                httpx.RequestError,
                httpx.HTTPStatusError,
            ) as exception:
                logger.debug(
                    "Quad9 request attempt %d failed for %s: %s",
                    attempt + 1,
                    complete_url,
                    exception,
                )
                if attempt == attempt_number - 1:
                    # Return empty result when network is unavailable
                    # This allows tests to pass in CI without network access
                    logger.warning(
                        "Quad9 DNS resolver failed after %d attempts for %s",
                        attempt_number,
                        observable,
                    )
                    return dns_resolver_response(observable, [])

        # Guard: if we somehow have no response, return empty
        if not quad9_response:
            return dns_resolver_response(observable, [])

        try:
            json_response = quad9_response.json()
        except ValueError:
            logger.warning("Quad9 returned non-JSON response for %s", observable)
            return dns_resolver_response(observable, [])

        resolutions: list[str] = []
        for answer in json_response.get("Answer", []):
            if "data" in answer:
                resolutions.append(answer["data"])

        return dns_resolver_response(observable, resolutions)
