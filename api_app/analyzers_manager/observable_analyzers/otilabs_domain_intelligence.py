# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from urllib.parse import quote, urlparse

import requests

from api_app.analyzers_manager.classes import ObservableAnalyzer
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from api_app.choices import Classification


class OTILabsDomainIntelligence(ObservableAnalyzer):
    """
    Look up a domain with the OTI Labs Domain Intelligence API: WHOIS/RDAP registration,
    DNS records, the TLS certificate, subdomains (live ones with their IPs) and
    SPF/DMARC/DKIM, in one request.
    """

    url: str = "https://domain-intelligence-api.p.rapidapi.com"
    _api_key_name: str

    @classmethod
    def update(cls) -> bool:
        pass

    def _domain(self) -> str:
        if self.observable_classification == Classification.URL:
            return (urlparse(self.observable_name).hostname or "").rstrip(".")
        return self.observable_name.strip().rstrip(".").lower()

    def run(self):
        domain = self._domain()
        if not domain:
            raise AnalyzerRunException(f"Could not get a domain from {self.observable_name}")

        try:
            response = requests.get(
                f"{self.url}/lookup/{quote(domain, safe='')}",
                headers={
                    "X-RapidAPI-Key": self._api_key_name,
                    "X-RapidAPI-Host": urlparse(self.url).hostname,
                    "Accept": "application/json",
                },
                timeout=30,
            )
        except requests.RequestException as e:
            raise AnalyzerRunException(e) from e

        if response.status_code in (401, 403):
            raise AnalyzerRunException(
                f"The API rejected the key (HTTP {response.status_code}). "
                "Use a RapidAPI key subscribed to the OTI Labs Domain Intelligence API."
            )
        if response.status_code == 429:
            raise AnalyzerRunException("Monthly quota or rate limit reached (HTTP 429).")
        if response.status_code != 200:
            raise AnalyzerRunException(f"Unexpected HTTP status {response.status_code}")

        try:
            return response.json()
        except ValueError as e:
            raise AnalyzerRunException(f"Invalid JSON response: {e}") from e
