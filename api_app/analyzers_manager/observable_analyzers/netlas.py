# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import requests

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from tests.mock_utils import MockUpResponse, if_mock_connections, patch


class Netlas(classes.ObservableAnalyzer):
    base_url: str = "https://app.netlas.io/api/whois_ip/"

    _api_key_name: str

    def config(self):
        super().config()
        self.query = self.observable_name

        self.headers = {"X-API-Key": f"{self._api_key_name}"}

        self.parameters = {"q": f"ip:{self.query}"}

    def run(self):
        try:
            response = requests.get(
                self.base_url, params=self.parameters, headers=self.headers
            )
            response.raise_for_status()
        except requests.RequestException as e:
            raise AnalyzerRunException(e)

        result = response.json()
        result_data = result["items"][0]["data"]
        return result_data

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
