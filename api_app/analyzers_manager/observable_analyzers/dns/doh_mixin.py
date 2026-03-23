import base64
import logging
from abc import ABCMeta
from urllib.parse import urlparse

import dns.message

from api_app.analyzers_manager.classes import BaseAnalyzerMixin
from api_app.choices import Classification

logger = logging.getLogger(__name__)


class DoHMixin(BaseAnalyzerMixin, metaclass=ABCMeta):
    def run(self) -> dict:
        pass

    url: str
    headers: dict = {"Accept": "application/dns-message"}
    query_type: str

    def convert_to_domain(self, observable: str, classification: str) -> str:
        if classification == Classification.URL:
            logger.debug(f"{self} extracting hostname from URL {observable}")
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
        encoded_query = base64.urlsafe_b64encode(wire_query).rstrip(b"=").decode("ascii")
        logger.info(f"{self.analyzer_name} encoded query for {observable}: {encoded_query}")
        return encoded_query

    def build_query_url(self, observable_name: str) -> str:
        encoded_query = self.encode_query(observable_name)
        return f"{self.url}?dns={encoded_query}"
