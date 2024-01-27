# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import requests

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from tests.mock_utils import MockUpResponse, if_mock_connections, patch


class Censys(classes.ObservableAnalyzer):
    """
    Censys search analyzer class. Analyzes IP addresses.
    Ugraded api endpoint v2
    Please apply secreats using: https://search.censys.io/account/api
    """

    base_url = "https://search.censys.io/api/v2"

    censys_analysis: str
    _api_id_name: str
    _api_secret_name: str

    def run(self):
        if self.censys_analysis == "search":
            uri = f"/hosts/{self.observable_name}"
        else:
            raise AnalyzerRunException(
                f"not supported observable type {self.observable_classification}."
                "Supported is IP"
            )
        try:
            response = requests.get(
                self.base_url + uri, auth=(self._api_id_name, self._api_secret_name)
            )
            response.raise_for_status()
        except requests.RequestException as e:
            raise AnalyzerRunException(e)

        return response.json()

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch(
                    "requests.get",
                    return_value=MockUpResponse({}, 200),
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)
