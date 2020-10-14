"""Check if the domains is reported as malicious in Quad9 database"""

import requests

from urllib.parse import urlparse
from api_app.script_analyzers import classes
from api_app.script_analyzers.observable_analyzers.dns.dns_responses import (
    malicious_detector_response,
)
from api_app.exceptions import AnalyzerRunException


class Quad9MaliciousDetector(classes.ObservableAnalyzer):
    """Retrieve malicious domain in Quad9 DB.
    Quad9 does not answer in case of DNS query for malicious domains.
    Perform one request to Quad9 and another to Google.
    In case of no response from Quad9 and response from Google,
    the domain in DNS query is malicious.
    """

    def run(self):
        observable = self.observable_name
        # for URLs we are checking the relative domain
        if self.observable_classification == "url":
            observable = urlparse(self.observable_name).hostname

        quad9_answer = self._quad9_dns_query(observable)
        # if Quad9 has not an answer the site could be malicious
        if not quad9_answer:
            # Google dns request
            google_answer = self._google_dns_query(observable)
            # if Google response, Quad9 marked the site as malicious,
            # elsewhere the site does not exist
            if google_answer:
                return malicious_detector_response(self.observable_name, True)

        return malicious_detector_response(self.observable_name, False)

    def _quad9_dns_query(self, observable):
        """Perform a DNS query with Quad9 service, return True if Quad9 answer the
        DNS query.

        :param observable: domain to resolve
        :type observable: str
        :return: True in case of answer for the DNS query else False.
        :rtype: bool
        """
        try:
            headers = {"Accept": "application/dns-json"}
            url = "https://dns.quad9.net:5053/dns-query"
            params = {"name": observable}

            quad9_response = requests.get(url, headers=headers, params=params)
            quad9_response.raise_for_status()
        except requests.RequestException as e:
            raise AnalyzerRunException(e)

        return True if quad9_response.json().get("Answer", None) else False

    def _google_dns_query(self, observable):
        """Perform a DNS query with Google service, return True if Google answer the
        DNS query.

        :param observable: domain to resolve
        :type observable: str
        :return: True in case of answer for the DNS query else False.
        :rtype: bool
        """
        try:
            params = {"name": observable}
            google_response = requests.get(
                "https://dns.google.com/resolve", params=params
            )
            google_response.raise_for_status()
        except requests.RequestException as e:
            raise AnalyzerRunException(e)

        return True if google_response.json().get("Answer", None) else False
