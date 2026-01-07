# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

"""Check if the domains is reported as malicious in DNS4EU database"""

import logging
from urllib.parse import urlparse
import requests

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from api_app.choices import Classification

from ..dns_responses import malicious_detector_response

logger = logging.getLogger(__name__)


class DNS4EUMaliciousDetector(classes.ObservableAnalyzer):
    """
    Check if a domain is malicious via DNS4EU
    """

    class NotADomain(Exception):
        """Exception for non-domain observables"""
        pass

    def update(self):
        """
        Required by IntelOwl Plugin base class.
        This analyzer does not require background updates.
        """
        pass

    def run(self):
        """
        Execute the analysis
        """
        observable = self.observable_name
        is_malicious = False
        try:
            # for URLs we are checking the relative domain
            if self.observable_classification == Classification.URL:
                observable = urlparse(self.observable_name).hostname
                if not observable:
                    raise self.NotADomain()

            params = {
                "name": observable,
                "type": "A",
            }
            headers = {"accept": "application/dns-json"}

            # Using the DNS4EU DoH endpoint
            response = requests.get(
                "https://doh.dns4eu.eu/dns-query",
                params=params,
                headers=headers,
                timeout=10
            )
            response.raise_for_status()
            response_dict = response.json()

            # DNS4EU Logic: If a domain is blocked/malicious, it typically
            # returns a 'status' or a specific sinkhole IP (like 0.0.0.0)
            if response_dict.get("Status") == 3:
                is_malicious = True

            # Also check if the answer points to a sinkhole
            answers = response_dict.get("Answer", [])
            for ans in answers:
                if ans.get("data") == "0.0.0.0":
                    is_malicious = True

        except requests.exceptions.RequestException:
            raise AnalyzerRunException("Connection to DNS4EU failed")
        except self.NotADomain:
            logger.info("not analyzing %s because not a domain", observable)

        return malicious_detector_response(self.observable_name, is_malicious)
    