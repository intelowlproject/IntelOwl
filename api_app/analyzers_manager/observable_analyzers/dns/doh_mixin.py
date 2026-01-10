import base64
import logging
from abc import ABCMeta
from urllib.parse import urlparse

import dns.message
import httpx

from api_app.analyzers_manager.classes import BaseAnalyzerMixin
from api_app.choices import Classification

logger = logging.getLogger(__name__)


class DoHMixin(BaseAnalyzerMixin, metaclass=ABCMeta):
    def run(self) -> dict:
        pass

    url: str
    headers: dict = {"Accept": "application/dns-message"}
    query_type: str

    @staticmethod
    def convert_to_domain(observable: str, classification: str) -> str:
        if classification == Classification.URL:
            logger.debug(f"Mullvad_DNS extracting hostname from URL {observable}")
            hostname = urlparse(observable).hostname
            observable = hostname
        return observable

    def encode_query(self, observable: str) -> str:
        """
        Constructs a DNS query for the given observable (domain) for an A record,
        converts it to wire format, and encodes it in URL-safe base64.
        """
        logger.info(f"Encoding DNS query for {observable}")
        query = dns.message.make_query(observable, dns.rdatatype.A)
        wire_query = query.to_wire()
        encoded_query = (
            base64.urlsafe_b64encode(wire_query).rstrip(b"=").decode("ascii")
        )
        logger.info(
            f"{self.analyzer_name} encoded query for {observable}: {encoded_query}"
        )
        return encoded_query

    def build_query_url(self, observable_name: str) -> str:
        encoded_query = self.encode_query(observable_name)
        return f"{self.url}?dns={encoded_query}"

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
                quad9_response = httpx.Client(http2=True).get(
                    complete_url, headers=self.headers, timeout=10
                )
            except httpx.ConnectError as exception:
                if attempt == attempt_number - 1:
                    raise exception
            else:
                quad9_response.raise_for_status()
                break

        dns_response = dns.message.from_wire(quad9_response.content)
        resolutions: list[str] = []
        for answer in dns_response.answer:
            for record in answer:
                if hasattr(record, "address"):
                    resolutions.append(record.address)
                elif hasattr(record, "target"):
                    resolutions.append(str(record.target))

        return resolutions
