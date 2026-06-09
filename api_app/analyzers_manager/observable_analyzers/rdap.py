# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging
from urllib.parse import urlparse

import requests

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from api_app.choices import Classification

logger = logging.getLogger(__name__)


class Rdap(classes.ObservableAnalyzer):
    """Query the public RDAP bootstrap (https://rdap.org) for an observable's
    registration data.

    RDAP (Registration Data Access Protocol, RFC 9082/9083) is the IETF-standard,
    free and unauthenticated successor to WHOIS. It returns structured JSON
    describing the registration of IP addresses, domains, and URLs (resolved to
    their host). The rdap.org bootstrap redirects each query to the authoritative
    RDAP server for the object.
    """

    url: str = "https://rdap.org"

    def update(self) -> bool:
        pass

    def run(self):
        if self.observable_classification == Classification.IP:
            path = f"ip/{self.observable_name}"
        elif self.observable_classification == Classification.DOMAIN:
            path = f"domain/{self.observable_name}"
        elif self.observable_classification == Classification.URL:
            hostname = urlparse(self.observable_name).hostname
            if not hostname:
                raise AnalyzerRunException(f"unable to extract a hostname from URL {self.observable_name}")
            path = f"domain/{hostname}"
        else:
            raise AnalyzerRunException(
                f"{self.observable_classification} is not a supported observable type "
                "for RDAP (supported: ip, domain, url)"
            )

        try:
            response = requests.get(
                f"{self.url}/{path}",
                headers={"Accept": "application/rdap+json"},
                timeout=10,
            )
            # RDAP returns 404 when the registry holds no record for the object;
            # treat that as a clean negative result rather than an error.
            if response.status_code == 404:
                return {"found": False}
            response.raise_for_status()
        except requests.RequestException as e:
            raise AnalyzerRunException(e)

        result = response.json()
        result["found"] = True
        return result
