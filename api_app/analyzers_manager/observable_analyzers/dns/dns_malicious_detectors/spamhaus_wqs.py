import logging

import requests

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from api_app.choices import Classification

from ..dns_responses import malicious_detector_response

logger = logging.getLogger(__name__)


class SpamhausWQS(classes.ObservableAnalyzer):
    url: str = "https://apibl.spamhaus.net/lookup/v1"
    _api_key: str = None

    def update(self):
        pass

    def run(self):
        headers = {"Authorization": f"Bearer {self._api_key}"}
        response = requests.get(
            url=f"""{self.url}/
            {"DBL" if self.observable_classification == Classification.DOMAIN.value else "AUTHBL"}
            /{self.observable_name}""",
            headers=headers,
        )
        # refer to the link for status code info
        # https://docs.spamhaus.com/datasets/docs/source/70-access-methods/web-query-service/060-api-info.html#http-response-status-codes
        if response.status_code == 200:
            # 200 - Found - The record is listed
            return malicious_detector_response(self.observable_name, True)
        elif response.status_code == 404:
            # 404 - Not found - The record is not listed
            return malicious_detector_response(self.observable_name, False)
        else:
            raise AnalyzerRunException(f"result not expected: {response.status_code}")
