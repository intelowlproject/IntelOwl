"""Module to perform Quad9 DoH (DNS over HTTPS) resolutions.
Quad9 does not respond in case of DNS queries to the malicious sites.
"""

import requests

from urllib.parse import urlparse
from api_app.script_analyzers import classes
from api_app.exceptions import AnalyzerRunException


class Quad9(classes.ObservableAnalyzer):
    """Perform DoH query to Quad9 and return no answer for the malicious sites."""

    def run(self):
        quad9_answer = self._quad9_dns_query()
        # if Quad9 has not an answer the site could be malicious
        if not quad9_answer:
            # Google dns request
            google_answer = self._google_dns_query()
            # if Google response, Quad9 marked the site as malicious,
            # elsewhere the site does not exist
            if google_answer:
                return {"malicious": True}

        return {"malicious": False}

    def _quad9_dns_query(self):
        """Perform a DNS query with Quad9 service, return True if Quad9 answer the
        DNS query.

        :return: True in case of answer for the DNS query else False.
        :rtype: bool
        """
        headers = {"Accept": "application/dns-json"}
        url = "https://dns.quad9.net:5053/dns-query"

        observable = self.observable_name
        # for URLs we are checking the relative domain
        if self.observable_classification == "url":
            observable = urlparse(self.observable_name).hostname
        params = {"name": observable}

        # Quad9 request
        try:
            quad9_response = requests.get(url, headers=headers, params=params)
            quad9_response.raise_for_status()
        except requests.RequestException as e:
            raise AnalyzerRunException(e)

        return True if quad9_response.json().get("Answer", None) else False

    def _google_dns_query(self):
        """Perform a DNS query with Google service, return True if Google answer the
        DNS query.

        :return: True in case of answer for the DNS query else False.
        :rtype: bool
        """
        observable = self.observable_name
        # for URLs we are checking the relative domain
        if self.observable_classification == "url":
            observable = urlparse(self.observable_name).hostname

        try:
            params = {"name": observable}
            google_response = requests.get(
                "https://dns.google.com/resolve", params=params
            )
            google_response.raise_for_status()
        except requests.RequestException as e:
            raise AnalyzerRunException(e)

        return True if google_response.json().get("Answer", None) else False
