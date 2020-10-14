"""Check if the domains is reported as malicious in CloudFlare database"""

import requests

from api_app.exceptions import AnalyzerRunException
from urllib.parse import urlparse
from api_app.script_analyzers.observable_analyzers.dns.dns_responses import (
    malicious_detector_response,
)
from api_app.script_analyzers import classes


class CloudFlareMaliciousDetector(classes.ObservableAnalyzer):
    """Resolve a DNS query with CloudFlare security endpoint,
    if response is 0.0.0.0 the domain in DNS query is malicious.
    """

    def run(self):
        try:
            is_malicious = False
            observable = self.observable_name
            # for URLs we are checking the relative domain
            if self.observable_classification == "url":
                observable = urlparse(self.observable_name).hostname

            client = requests.session()
            params = {
                "name": observable,
                "type": "A",
                "ct": "application/dns-json",
            }
            response = client.get(
                "https://security.cloudflare-dns.com/dns-query", params=params
            )
            response.raise_for_status()
            response_dict = response.json()

            response_answer = response_dict.get("Answer", [])
            if response_answer:
                resolution = response_answer[0].get("data", "")
                # CloudFlare answers with 0.0.0.0 if the domain is known as malicious
                if resolution == "0.0.0.0":
                    is_malicious = True

        except requests.exceptions.RequestException:
            raise AnalyzerRunException("Connection to CloudFlare failed")

        return malicious_detector_response(self.observable_name, is_malicious)
