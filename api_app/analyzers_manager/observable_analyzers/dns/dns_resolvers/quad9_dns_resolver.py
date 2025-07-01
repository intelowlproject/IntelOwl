# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

"""Quad9 DNS resolutions"""
import logging

import dns.message
import httpx

from api_app.analyzers_manager import classes
from tests.mock_utils import MockUpResponse, if_mock_connections, patch

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
        for attempt in range(0, attempt_number):
            try:
                quad9_response = httpx.Client(http2=True).get(
                    complete_url, headers=self.headers, timeout=10
                )
            except httpx.ConnectError as exception:
                # if the last attempt fails, raise an error
                if attempt == attempt_number - 1:
                    raise exception
            else:
                quad9_response.raise_for_status()

        dns_response = dns.message.from_wire(quad9_response.content)
        resolutions: list[str] = []
        for answer in dns_response.answer:
            resolutions.extend([resolution.address for resolution in answer])

        return dns_resolver_response(observable, resolutions)

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch(
                    "httpx.Client.get",
                    return_value=MockUpResponse(
                        {
                            "status": "success",
                            "data": "example.com. 236 IN A 23.215.0.138",
                            "message": "DNS query for example.com completed successfully.",
                        },
                        200,
                        content=b"pn\x01\x03\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01",
                    ),
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)
