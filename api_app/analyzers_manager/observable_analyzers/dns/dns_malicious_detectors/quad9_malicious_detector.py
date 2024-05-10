# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

"""Check if the domains is reported as malicious in Quad9 database"""

import logging
from typing import Tuple
from urllib.parse import urlparse

import requests

from api_app.analyzers_manager import classes
from tests.mock_utils import MockUpResponse, if_mock_connections, patch

from ..dns_responses import malicious_detector_response

logger = logging.getLogger(__name__)


class Quad9MaliciousDetector(classes.ObservableAnalyzer):
    """Check if a domain is malicious by Quad9 public resolver.
    Quad9 does not answer in the case a malicious domain is queried.
    However, we need to perform another check to understand if that domain was blocked
    by the resolver or if it just does not exist.
    So we perform one request to Quad9 and another one to Google.
    In the case of empty response from Quad9 and a non-empty response from Google,
    we can guess that the domain was in the Quad9 blacklist.
    """

    HEADERS = {"Accept": "application/dns-json"}
    QUAD9_URL = "https://dns.quad9.net:5053/dns-query"
    GOOGLE_URL = "https://dns.google.com/resolve"

    def update(self) -> bool:
        pass

    def run(self):
        observable = self.observable_name
        # for URLs we are checking the relative domain
        if self.observable_classification == self.ObservableTypes.URL:
            observable = urlparse(self.observable_name).hostname

        quad9_answer, timeout = self._quad9_dns_query(observable)
        # if Quad9 has not an answer the site could be malicious
        if not quad9_answer:
            # Google dns request
            google_answer = self._google_dns_query(observable)
            # if Google response, Quad9 marked the site as malicious,
            # elsewhere the site does not exist
            if google_answer:
                return malicious_detector_response(self.observable_name, True)

        return malicious_detector_response(self.observable_name, False, timeout)

    def _quad9_dns_query(self, observable) -> Tuple[bool, bool]:
        """Perform a DNS query with Quad9 service, return True if Quad9 answer the
        DNS query with a non-empty response.

        :param observable: domain to resolve
        :type observable: str
        :return: True in case of answer for the DNS query else False.
        :rtype: bool
        """
        answer_found = False
        timeout = False
        params = {"name": observable}

        quad9_response = requests.get(
            self.QUAD9_URL, headers=self.HEADERS, params=params
        )
        if quad9_response.status_code == 503:
            msg = (
                "503 status code! "
                "It may be normal for this service to"
                " happen from time to time"
            )
            logger.info(msg)
            self.report.errors.append(msg)
            timeout = True
            return answer_found, timeout
        quad9_response.raise_for_status()
        answer_found = bool(quad9_response.json().get("Answer", None))

        return answer_found, timeout

    def _google_dns_query(self, observable) -> bool:
        """Perform a DNS query with Google service, return True if Google answer the
        DNS query.

        :param observable: domain to resolve
        :type observable: str
        :return: True in case of answer for the DNS query else False.
        :rtype: bool
        """
        params = {"name": observable}
        google_response = requests.get(self.GOOGLE_URL, params=params)
        google_response.raise_for_status()

        return bool(google_response.json().get("Answer", None))

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch(
                    "requests.get",
                    return_value=MockUpResponse({"Answer": False}, 200),
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)
