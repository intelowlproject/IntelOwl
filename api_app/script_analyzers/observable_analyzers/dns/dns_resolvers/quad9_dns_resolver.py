"""Quad9 DNS resolutions"""

import requests

from urllib.parse import urlparse
from api_app.exceptions import AnalyzerRunException
from api_app.script_analyzers import classes
from api_app.script_analyzers.observable_analyzers.dns.dns_responses import (
    dns_resolver_response,
)


class Quad9DNSResolver(classes.ObservableAnalyzer):
    """Resolve a DNS query with Quad9"""

    def set_config(self, additional_config_params):
        self._query_type = additional_config_params.get("query_type", "A")

    def run(self):
        try:
            observable = self.observable_name
            # for URLs we are checking the relative domain
            if self.observable_classification == "url":
                observable = urlparse(self.observable_name).hostname

            headers = {"Accept": "application/dns-json"}
            url = "https://dns.quad9.net:5053/dns-query"
            params = {"name": observable, "type": self._query_type}

            quad9_response = requests.get(url, headers=headers, params=params)
            quad9_response.raise_for_status()
            resolutions = quad9_response.json().get("Answer", [])
        except requests.RequestException:
            raise AnalyzerRunException(
                "an error occurred during the connection to Quad9"
            )

        return dns_resolver_response(self.observable_name, resolutions)
