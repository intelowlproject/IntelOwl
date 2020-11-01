"""CloudFlare DNS resolutions"""

import requests

from urllib.parse import urlparse
from api_app.exceptions import AnalyzerRunException
from api_app.script_analyzers import classes
from api_app.script_analyzers.observable_analyzers.dns.dns_responses import (
    dns_resolver_response,
)

import logging

logger = logging.getLogger(__name__)


class CloudFlareDNSResolver(classes.ObservableAnalyzer):
    """Resolve a DNS query with CloudFlare"""

    def set_config(self, additional_config_params):
        self._query_type = additional_config_params.get("query_type", "A")

    def run(self):
        try:
            observable = self.observable_name
            # for URLs we are checking the relative domain
            if self.observable_classification == "url":
                observable = urlparse(self.observable_name).hostname

            client = requests.session()
            params = {
                "name": observable,
                "type": self._query_type,
                "ct": "application/dns-json",
            }
            response = client.get("https://cloudflare-dns.com/dns-query", params=params)
            response.raise_for_status()
            response_dict = response.json()

            resolutions = response_dict.get("Answer", None)

        except requests.exceptions.RequestException:
            raise AnalyzerRunException(
                "An error occurred during the connection to CloudFlare"
            )

        return dns_resolver_response(self.observable_name, resolutions)
