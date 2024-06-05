import logging
from typing import Tuple
from urllib.parse import urlparse
import base64
import dns.message
import requests

from api_app.analyzers_manager import classes
from tests.mock_utils import MockUpResponse, if_mock_connections, patch

from ..dns_responses import malicious_detector_response

logger = logging.getLogger(__name__)

class AdGuard(classes.ObservableAnalyzer):
    """Check if a domain is malicious by AdGuard public resolver.
    AdGuard does not answer in the case a malicious domain is queried.
    However, we need to perform another check to understand if that domain was blocked
    by the resolver or if it just does not exist.
    """

    HEADERS = {"Accept": "application/dns-json"}

    url_no_filter= "https://unfiltered.adguard-dns.com/dns-query"
    url_dns_filter= "https://dns.adguard-dns.com/dns-query"

    def update(self) -> bool:
        pass

    def run(self):
        observable = self.observable_name
        # for URLs we are checking the relative domain
        if self.observable_classification == self.ObservableTypes.URL:
            observable = urlparse(self.observable_name).hostname

        query = dns.message.make_query('example.com', dns.rdatatype.A)
        query_wire = query.to_wire()
        query_base64url = base64.urlsafe_b64encode(query_wire).rstrip(b'=')
        
        params = {"dns": observable}
        response = requests.get(
            f"https://unfiltered.adguard-dns.com/dns-query?dns={query_base64url.decode()}", headers={"Accept": "application/dns-json"},
        )
        response2 = requests.get(
            f"https://dns.adguard-dns.com/dns-query?dns={query_base64url.decode()}", headers={"Accept": "application/dns-json"},
        )
        logger.info(f"AdGuard responsee: {response.text}")
        logger.info(f"AdGuard responsee2: {response2.text}")

        return (response.text, response2.text)