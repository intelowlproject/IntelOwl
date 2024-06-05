import logging
from urllib.parse import urlparse

import requests

from api_app.analyzers_manager import classes

logger = logging.getLogger(__name__)


class AdGuard(classes.ObservableAnalyzer):
    """Check if a domain is malicious by AdGuard public resolver."""

    HEADERS = {"Accept": "application/dns-json"}

    url_no_filter = "https://unfiltered.adguard-dns.com/dns-query"
    url_dns_filter = "https://dns.adguard-dns.com/dns-query"

    def update(self) -> bool:
        pass

    def run(self):
        observable = self.observable_name
        # for URLs we are checking the relative domain
        if self.observable_classification == self.ObservableTypes.URL:
            observable = urlparse(self.observable_name).hostname
        params = {"dns": observable}
        response1 = requests.get(
            "https://unfiltered.adguard-dns.com/dns-query",
            params=params,
            headers={"Accept": "application/dns-json"},
        )
        response2 = requests.get(
            "https://dns.adguard-dns.com/dns-query?",
            params=params,
            headers={"Accept": "application/dns-json"},
        )

        return {"response1": response1.text, "response2": response2.text}
