# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

"""Default DNS resolutions"""

import ipaddress
import logging
import socket
from urllib.parse import urlparse

import dns.resolver

from api_app.analyzers_manager import classes
from api_app.choices import Classification

from ..dns_responses import dns_resolver_response

logger = logging.getLogger(__name__)


class ClassicDNSResolver(classes.ObservableAnalyzer):
    """Resolve a DNS query with Default resolver"""

    query_type: str

    def run(self):
        resolutions = []
        timeout = False
        if self.observable_classification == Classification.IP:
            try:
                ipaddress.ip_address(self.observable_name)
                hostname, alias, _ = socket.gethostbyaddr(self.observable_name)
                if alias:
                    resolutions.extend(alias)
                if hostname:
                    resolutions.append(hostname)
            except (socket.gaierror, socket.herror):
                logger.info(f"No resolution for ip {self.observable_name}")
                self.report.errors.append(f"No resolution for ip {self.observable_name}")
                resolutions = []
            except socket.timeout:
                message = f"request for {self.observable_name} for classic DNS triggered timeout"
                logger.warning(message)
                self.report.errors.append(message)
                timeout = True

        elif self.observable_classification in [
            Classification.DOMAIN,
            Classification.URL,
        ]:
            observable = self.observable_name
            # for URLs we are checking the relative domain
            if self.observable_classification == Classification.URL:
                observable = urlparse(self.observable_name).hostname

            try:
                dns_resolutions = dns.resolver.resolve(observable, self.query_type)
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
                logger.info(f"No resolution for {self.observable_classification} {self.observable_name}")
            except dns.resolver.LifetimeTimeout as e:
                logger.warning(
                    f"No resolution for {self.observable_classification} {self.observable_name}. Reason {e}",
                    stack_info=True,
                )
                self.report.errors.append(str(e))
                timeout = True

        return dns_resolver_response(self.observable_name, resolutions, timeout)
