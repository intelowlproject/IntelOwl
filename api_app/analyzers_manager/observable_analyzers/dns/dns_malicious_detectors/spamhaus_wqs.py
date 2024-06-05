import logging

import requests

from api_app.analyzers_manager import classes
from tests.mock_utils import MockUpResponse, if_mock_connections, patch

from ..dns_responses import malicious_detector_response

logger = logging.getLogger(__name__)


class SpamhausWQS(classes.ObservableAnalyzer):
    url: str = "https://apibl.spamhaus.net/lookup/v1"
    _api_key: str = None

    def run(self):
        headers = {"Authorization": f"Bearer {self._api_key}"}

        if self.observable_classification == self.ObservableTypes.DOMAIN.value:
            if len(self.observable_name.split(".")) > 2:
                # "www.google.xyz.yzx..." to "google"
                self.observable_name = self.observable_name.split(".")[1]
            else:
                # "google.com" to "google" or "google" to "google"
                self.observable_name = self.observable_name.split(".")[0]
            response = requests.get(
                url=f"{self.url}/DBL/{self.observable_name}", headers=headers
            )
        if self.observable_classification == self.ObservableTypes.IP.value:
            response = requests.get(
                url=f"{self.url}/AUTHBL/{self.observable_name}", headers=headers
            )
        if response.json()["status"] == 404:
            # 404 - Not found - The record is not listed
            return malicious_detector_response(self.observable_name, False)
        response.raise_for_status()
        return malicious_detector_response(self.observable_name, True)

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch(
                    "requests.get",
                    return_value=MockUpResponse({"resp": [1020], "status": 200}, 200),
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)
