# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

"""CloudFlare DNS resolutions"""

import logging
from urllib.parse import urlparse

import requests

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from api_app.choices import Classification

from ..dns_responses import dns_resolver_response

logger = logging.getLogger(__name__)


class CloudFlareDNSResolver(classes.ObservableAnalyzer):
    """Resolve a DNS query with CloudFlare"""

    query_type: str

    def run(self):
        try:
            observable = self.observable_name
            # for URLs we are checking the relative domain
            if self.observable_classification == Classification.URL:
                observable = urlparse(self.observable_name).hostname

            params = {
                "name": observable,
                "type": self.query_type,
            }
            headers = {"accept": "application/dns-json"}
            response = requests.get("https://cloudflare-dns.com/dns-query", params=params, headers=headers)
            response.raise_for_status()
            response_dict = response.json()

            resolutions = response_dict.get("Answer", None)

        except requests.exceptions.RequestException as error:
            raise AnalyzerRunException(f"An error occurred during the connection to CloudFlare: {error}")
        return dns_resolver_response(self.observable_name, resolutions)
