# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

"""Google DNS resolutions"""

import logging
from urllib.parse import urlparse

import requests

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from api_app.choices import Classification

from ..dns_responses import dns_resolver_response

logger = logging.getLogger(__name__)


class GoogleDNSResolver(classes.ObservableAnalyzer):
    """Resolve a DNS query with Google"""

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
            response = requests.get("https://dns.google.com/resolve", params=params)
            response.raise_for_status()
            data = response.json()
            resolutions = data.get("Answer", None)
        except requests.exceptions.RequestException:
            raise AnalyzerRunException("an error occurred during the connection to Google")

        return dns_resolver_response(self.observable_name, resolutions)
