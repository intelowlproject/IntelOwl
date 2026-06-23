# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import ipaddress
from urllib.parse import urlparse

import requests

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from api_app.choices import Classification


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
        # No local data to refresh; rdap.org is queried live on every run.
        return False

    @staticmethod
    def _path_for_host(host: str) -> str:
        """Pick the RDAP endpoint for a host: ``ip/`` for an IP literal
        (the host of a URL can be one), ``domain/`` otherwise."""
        try:
            ipaddress.ip_address(host)
        except ValueError:
            return f"domain/{host}"
        return f"ip/{host}"

    def run(self):
        if self.observable_classification == Classification.IP:
            path = f"ip/{self.observable_name}"
        elif self.observable_classification == Classification.DOMAIN:
            path = f"domain/{self.observable_name}"
        elif self.observable_classification == Classification.URL:
            hostname = urlparse(self.observable_name).hostname
            if not hostname:
                raise AnalyzerRunException(f"unable to extract a hostname from URL {self.observable_name}")
            path = self._path_for_host(hostname)
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
            raise AnalyzerRunException(str(e)) from e

        try:
            result = response.json()
        except ValueError as e:
            raise AnalyzerRunException(f"RDAP server returned a non-JSON response: {e}") from e
        result["found"] = True
        return result
