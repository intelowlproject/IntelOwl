# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import requests

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import AnalyzerRunException


class Censys(classes.ObservableAnalyzer):
    """
    Censys search analyzer class. Analyzes IP addresses.
    Ugraded api endpoint v2
    Please apply secreats using: https://search.censys.io/account/api
    """

    def update(self):
        pass

    url = "https://search.censys.io/api/v2"

    censys_analysis: str
    _api_id_name: str
    _api_secret_name: str

    def run(self):
        if self.censys_analysis == "search":
            uri = f"/hosts/{self.observable_name}"
        else:
            raise AnalyzerRunException(
                f"not supported observable type {self.observable_classification}. Supported is IP."
            )
        response = requests.get(
            self.url + uri,
            auth=(self._api_id_name, self._api_secret_name),
            headers={
                "Accept": "application/json",
            },
        )
        response.raise_for_status()

        return response.json()
