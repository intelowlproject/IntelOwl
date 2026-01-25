# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

"""Check if the domains is reported as malicious in DNS4EU database"""

import logging
from ipaddress import AddressValueError, IPv4Address
from urllib.parse import urlparse

import requests

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from api_app.choices import Classification

from ..dns_responses import malicious_detector_response

logger = logging.getLogger(__name__)


class DNS4EUMaliciousDetector(classes.ObservableAnalyzer):
    class NotADomain(Exception):
        pass

    def run(self):
        observable = self.observable_name
        is_malicious = False
        try:
            # for URLs we are checking the relative domain
            if self.observable_classification == Classification.URL:
                observable = urlparse(self.observable_name).hostname
                try:
                    IPv4Address(observable)
                except AddressValueError:
                    pass
                else:
                    raise self.NotADomain()

            params = {
                "name": observable,
                "type": "A",
            }
            headers = {"accept": "application/dns-json"}
            # Use protective endpoint to check for blocking
            response = requests.get(
                "https://protective.joindns4.eu/dns-query",
                params=params,
                headers=headers,
            )
            response.raise_for_status()
            response_dict = response.json()

            # DNS4EU blocks by returning 0.0.0.0 or specific sinkhole IPs
            # Valid answers are in "Answer" section
            answers = response_dict.get("Answer", [])
            for answer in answers:
                data = answer.get("data", "")
                if data in ("0.0.0.0", "51.15.69.11"):
                    is_malicious = True
                    break

        except requests.exceptions.RequestException:
            raise AnalyzerRunException("Connection to DNS4EU failed")
        except self.NotADomain:
            logger.info(f"not analyzing {observable} because not a domain")

        return malicious_detector_response(self.observable_name, is_malicious)

    @classmethod
    def update(cls) -> bool:
        return True
