# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

"""Check if the domains is reported as malicious in CloudFlare database"""

from urllib.parse import urlparse

import requests

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from tests.mock_utils import MockUpResponse, if_mock_connections, patch

from ..dns_responses import malicious_detector_response


class CloudFlareMaliciousDetector(classes.ObservableAnalyzer):
    """Resolve a DNS query with CloudFlare security endpoint,
    if response is 0.0.0.0 the domain in DNS query is malicious.
    """

    def run(self):
        try:
            is_malicious = False
            observable = self.observable_name
            # for URLs we are checking the relative domain
            if self.observable_classification == self.ObservableTypes.URL:
                observable = urlparse(self.observable_name).hostname

            params = {
                "name": observable,
                "type": "A",
            }
            headers = {"accept": "application/dns-json"}
            response = requests.get(
                "https://security.cloudflare-dns.com/dns-query",
                params=params,
                headers=headers,
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

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch(
                    "requests.get",
                    return_value=MockUpResponse({"Answer": [{"data": "0.0.0.0"}]}, 200),
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)
