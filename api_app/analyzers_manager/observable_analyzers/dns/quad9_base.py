# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

"""Base class for Quad9 analyzers"""

import logging
from abc import ABCMeta

import dns.message
import httpx

from .doh_mixin import DoHMixin

logger = logging.getLogger(__name__)


class Quad9Base(DoHMixin, metaclass=ABCMeta):
    """Base class for Quad9 DNS analyzers with shared query functionality."""

    url: str = "https://dns.quad9.net/dns-query"

    def quad9_dns_query(self, observable: str) -> list[str]:
        """Perform a DNS query with Quad9 service.

        :param observable: domain to resolve
        :type observable: str
        :return: List of DNS resolutions
        :rtype: list[str]
        """
        complete_url = self.build_query_url(observable)

        attempt_number = 3
        quad9_response = None
        for attempt in range(attempt_number):
            try:
                quad9_response = httpx.Client(http2=True).get(complete_url, headers=self.headers, timeout=10)
            except httpx.ConnectError as exception:
                if attempt == attempt_number - 1:
                    raise exception
            else:
                quad9_response.raise_for_status()
                break

        dns_response = dns.message.from_wire(quad9_response.content)
        resolutions: list[str] = []
        # A/AAAA resolve via `.address` and CNAME/NS via `.target` — these point to real infrastructure.
        # TXT, MX, and other records are metadata and ignored for malicious host detection.
        for answer in dns_response.answer:
            for record in answer:
                if hasattr(record, "address"):
                    resolutions.append(record.address)
                elif hasattr(record, "target"):
                    resolutions.append(str(record.target))

        return resolutions
