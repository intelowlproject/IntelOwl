# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

"""Check if the domains is reported as malicious in Quad9 database"""
import logging

import requests

from api_app.analyzers_manager import classes

from ..dns_responses import malicious_detector_response
from ..quad9_base import Quad9Base

logger = logging.getLogger(__name__)


class Quad9MaliciousDetector(Quad9Base, classes.ObservableAnalyzer):
    """Check if a domain is malicious by Quad9 public resolver.
    Quad9 does not answer in the case a malicious domain is queried.
    However, we need to perform another check to understand if that domain was blocked
    by the resolver or if it just does not exist.
    So we perform one request to Quad9 and another one to Google.
    In the case of empty response from Quad9 and a non-empty response from Google,
    we can guess that the domain was in the Quad9 blacklist.
    """

    google_url: str = "https://dns.google.com/resolve"

    def update(self) -> bool:
        pass

    def run(self):

        observable = self.convert_to_domain(
            self.observable_name, self.observable_classification
        )

        resolutions = self.quad9_dns_query(observable)
        quad9_answer = bool(resolutions)
        # if Quad9 has not an answer the site could be malicious
        if not quad9_answer:
            # Google dns request
            google_answer = self._google_dns_query(observable)
            # if Google response, Quad9 marked the site as malicious,
            # elsewhere the site does not exist
            if google_answer:
                return malicious_detector_response(self.observable_name, True)

        return malicious_detector_response(self.observable_name, False)

    def _google_dns_query(self, observable) -> bool:
        """Perform a DNS query with Google service, return True if Google answer the
        DNS query.

        :param observable: domain to resolve
        :type observable: str
        :return: True in case of answer for the DNS query else False.
        :rtype: bool
        """
        params = {"name": observable}
        google_response = requests.get(self.google_url, params=params)
        google_response.raise_for_status()

        return bool(google_response.json().get("Answer", None))
