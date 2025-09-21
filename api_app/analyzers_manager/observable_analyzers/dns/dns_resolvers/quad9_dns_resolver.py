# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

"""Quad9 DNS resolutions"""
from urllib.parse import urlparse

import requests

from api_app.analyzers_manager import classes
from api_app.choices import Classification
from tests.mock_utils import MockUpResponse, if_mock_connections, patch

from ..dns_responses import dns_resolver_response


class Quad9DNSResolver(classes.ObservableAnalyzer):
    """Resolve a DNS query with Quad9"""

    url: str = "https://dns.quad9.net:5053/dns-query"
    headers: dict = {"Accept": "application/dns-json"}
    query_type: str

    def run(self):
        observable = self.observable_name
        # for URLs we are checking the relative domain
        if self.observable_classification == Classification.URL:
            observable = urlparse(self.observable_name).hostname

        params = {"name": observable, "type": self.query_type}

        attempt_number = 3
        for attempt in range(attempt_number):
            try:
                quad9_response = requests.get(
                    self.url, headers=self.headers, params=params, timeout=10
                )
            except requests.exceptions.ConnectionError as exception:
                if attempt == attempt_number - 1:
                    raise exception
            else:
                quad9_response.raise_for_status()
                break

        raw_answers = quad9_response.json().get("Answer", []) or []

        # normalize records to avoid issues with missing fields or CNAMEs
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

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch(
                    "requests.get",
                    return_value=MockUpResponse(
                        {
                            "Answer": [
                                {"type": 1, "data": "1.2.3.4"},
                                {"type": 5, "data": "example.com"},
                            ]
                        },
                        200,
                    ),
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)
