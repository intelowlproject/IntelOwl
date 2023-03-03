# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

"""Quad9 DNS resolutions"""

from urllib.parse import urlparse

import requests

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from tests.mock_utils import MockResponse, if_mock_connections, patch

from ..dns_responses import dns_resolver_response


class DNS0EUResolver(classes.ObservableAnalyzer):
    """Resolve a DNS query with DNS0.eu"""

    query_type: str

    def run(self):
        try:
            observable = self.observable_name
            # for URLs we are checking the relative domain
            if self.observable_classification == "url":
                observable = urlparse(self.observable_name).hostname

            headers = {"Accept": "application/dns-json"}
            url = "https://dns0.eu"
            params = {"name": observable, "type": self.query_type}

            response = requests.get(url, headers=headers, params=params)
            response.raise_for_status()
            resolutions = response.json().get("Answer", [])
        except requests.RequestException:
            raise AnalyzerRunException(
                "an error occurred during the connection to DNS0"
            )

        return dns_resolver_response(self.observable_name, resolutions)

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch(
                    "requests.get",
                    return_value=MockResponse({"Answer": ["test1", "test2"]}, 200),
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)
