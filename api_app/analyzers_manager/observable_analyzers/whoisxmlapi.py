# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import requests

from api_app.analyzers_manager import classes
from tests.mock_utils import MockUpResponse, if_mock_connections, patch


class Whoisxmlapi(classes.ObservableAnalyzer):
    url: str = "https://www.whoisxmlapi.com/whoisserver/WhoisService"

    _api_key_name: str

    def run(self):
        params = {
            "apiKey": self._api_key_name,
            "domainName": self.observable_name,
            "outputFormat": "JSON",
        }
        response = requests.get(self.url, params=params)
        response.raise_for_status()

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
