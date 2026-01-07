# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

"""Resolve a DNS query with DNS4EU"""

import logging
from urllib.parse import urlparse
import requests

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from api_app.choices import Classification
from ..dns_responses import dns_resolver_response

logger = logging.getLogger(__name__)


class DNS4EUResolver(classes.ObservableAnalyzer):
    """Resolve a DNS query with DNS4EU"""

    class NotADomain(Exception):
        """Exception for non-domain observables"""
        pass

    # Pointing to the new DNS4EU endpoint
    url = "https://doh.dns4eu.eu/dns-query"
    headers = {"Accept": "application/dns-json"}

    query_type: str

    def update(self):
        """
        Required by IntelOwl Plugin base class.
        This analyzer does not require background updates.
        """
        pass

    def run(self):
        """
        Execute the DNS resolution
        """
        observable = self.observable_name
        resolutions = None
        try:
            if self.observable_classification == Classification.URL:
                observable = urlparse(self.observable_name).hostname
                # Basic check to ensure it's not a raw IP
                if not observable:
                    raise self.NotADomain()

            params = {"name": observable, "type": self.query_type}

            # Sending the request to the new DNS4EU service
            response = requests.get(
                self.url, 
                headers=self.headers, 
                params=params,
                timeout=10
            )
            response.raise_for_status()
            resolutions = response.json().get("Answer", [])

        except requests.RequestException:
            # Error message updated to reflect DNS4EU
            raise AnalyzerRunException(
                "an error occurred during the connection to DNS4EU"
            )
        except self.NotADomain:
            logger.info("not analyzing %s because not a domain", observable)

        return dns_resolver_response(self.observable_name, resolutions)
    