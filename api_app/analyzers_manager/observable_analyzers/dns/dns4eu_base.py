# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging
from ipaddress import AddressValueError, IPv4Address
from urllib.parse import urlparse

import dns.query
import httpx

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from api_app.choices import Classification

logger = logging.getLogger(__name__)


class DNS4EUBase(classes.ObservableAnalyzer):
    """Base class for DNS4EU analyzers"""

    headers = {"User-Agent": "IntelOwl (https://github.com/intelowlproject/IntelOwl)"}

    def run(self):
        raise NotImplementedError

    @classmethod
    def update(cls) -> bool:
        return True

    def _get_observable_domain(self):
        observable = self.observable_name
        # for URLs we are checking the relative domain
        if self.observable_classification == Classification.URL:
            try:
                observable = urlparse(self.observable_name).hostname
            except Exception:
                raise AnalyzerRunException(f"Invalid URL: {self.observable_name}")

            try:
                IPv4Address(observable)
            except AddressValueError:
                pass
            else:
                raise AnalyzerRunException(f"{observable} is an IP address, not a domain.")
        return observable

    def _perform_dns_query(self, query, url, timeout=30):
        with httpx.Client(http2=True, headers=self.headers) as client:
            return dns.query.https(query, url, session=client, timeout=timeout)
