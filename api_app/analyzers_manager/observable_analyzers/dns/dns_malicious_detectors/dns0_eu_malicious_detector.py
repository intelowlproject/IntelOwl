# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

"""Check if the domains is reported as malicious in DNS0.eu database"""

from urllib.parse import urlparse

import requests

from api_app.analyzers_manager import classes
from api_app.exceptions import AnalyzerRunException
from tests.mock_utils import MockResponse, if_mock_connections, patch

from ..dns_responses import malicious_detector_response


class DNS0EUMaliciousDetector(classes.ObservableAnalyzer):
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
                "https://zero.dns0.eu",
                params=params,
                headers=headers,
            )
            response.raise_for_status()
            response_dict = response.json()

            response_answer = response_dict.get("Authority", [])
            if response_answer:
                resolution = response_answer[0].get("data", "")
                # CloudFlare answers with 0.0.0.0 if the domain is known as malicious
                if "negative-caching.dns0.eu" in resolution:
                    is_malicious = True

        except requests.exceptions.RequestException:
            raise AnalyzerRunException("Connection to DNS0 failed")

        return malicious_detector_response(self.observable_name, is_malicious)

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch(
                    "requests.get",
                    return_value=MockResponse(
                        {"Answer": [{"data": "negative-caching.dns0.eu"}]}, 200
                    ),
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)
