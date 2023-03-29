# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

"""Default DNS resolutions"""

import ipaddress
import logging
import socket
from urllib.parse import urlparse

import dns.resolver

from api_app.analyzers_manager import classes

from ..dns_responses import dns_resolver_response

logger = logging.getLogger(__name__)


class ClassicDNSResolver(classes.ObservableAnalyzer):
    """Resolve a DNS query with Default resolver"""

    query_type: str

    def run(self):
        resolutions = []
        if self.observable_classification == self.ObservableTypes.IP:
            try:
                ipaddress.ip_address(self.observable_name)
                hostname, alias, _ = socket.gethostbyaddr(self.observable_name)
                if alias:
                    resolutions.extend(alias)
                if hostname:
                    resolutions.append(hostname)
            except (socket.gaierror, socket.herror):
                logger.warning(f"No resolution for ip {self.observable_name}")
                self.report.errors.append(
                    f"No resolution for ip {self.observable_name}"
                )
                resolutions = []
        elif self.observable_classification in [
            self.ObservableTypes.DOMAIN,
            self.ObservableTypes.URL,
        ]:
            observable = self.observable_name
            # for URLs we are checking the relative domain
            if self.observable_classification == self.ObservableTypes.URL:
                observable = urlparse(self.observable_name).hostname

            try:
                dns_resolutions = dns.resolver.query(observable, self.query_type)
                for resolution in dns_resolutions:
                    element = {
                        "TTL": dns_resolutions.rrset.ttl,
                        "data": resolution.to_text(),
                        "name": dns_resolutions.qname.to_text(),
                        "type": dns_resolutions.rdtype,
                    }
                    resolutions.append(element)
            except (
                dns.resolver.NXDOMAIN,
                dns.resolver.NoAnswer,
                dns.resolver.NoNameservers,
            ):
                logger.warning(
                    f"No resolution for "
                    f"{self.observable_classification} {self.observable_name}"
                )
                resolutions = []

        return dns_resolver_response(self.observable_name, resolutions)

    @classmethod
    def _monkeypatch(cls):
        patches = []
        return super()._monkeypatch(patches=patches)
