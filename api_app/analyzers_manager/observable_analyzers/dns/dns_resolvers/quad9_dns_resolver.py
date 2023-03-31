# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

"""Quad9 DNS resolutions"""

from urllib.parse import urlparse

import requests

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from tests.mock_utils import MockUpResponse, if_mock_connections, patch

from ..dns_responses import dns_resolver_response


class Quad9DNSResolver(classes.ObservableAnalyzer):
    """Resolve a DNS query with Quad9"""

    query_type: str

    def run(self):
        try:
            observable = self.observable_name
            # for URLs we are checking the relative domain
            if self.observable_classification == "url":
                observable = urlparse(self.observable_name).hostname

            headers = {"Accept": "application/dns-json"}
            url = "https://dns.quad9.net:5053/dns-query"
            params = {"name": observable, "type": self.query_type}

            quad9_response = requests.get(url, headers=headers, params=params)
            quad9_response.raise_for_status()
            resolutions = quad9_response.json().get("Answer", [])
        except requests.RequestException:
            raise AnalyzerRunException(
                "an error occurred during the connection to Quad9"
            )

        return dns_resolver_response(self.observable_name, resolutions)

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch(
                    "requests.get",
                    return_value=MockUpResponse({"Answer": ["test1", "test2"]}, 200),
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)
