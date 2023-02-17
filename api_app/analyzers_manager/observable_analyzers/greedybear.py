# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import requests

from api_app.analyzers_manager.classes import ObservableAnalyzer
from api_app.analyzers_manager.exceptions import AnalyzerConfigurationException
from tests.mock_utils import MockResponse, if_mock_connections, patch


class GreedyBear(ObservableAnalyzer):
    def set_params(self, params):
        self.__api_key = self._secrets["api_key_name"]
        if not self.__api_key:
            raise AnalyzerConfigurationException("API key is required")
        self.url = params.get("url", "https://greedybear.honeynet.org")

    def run(self):
        headers = {
            "Authorization": "Token " + self.__api_key,
            "Accept": "application/json",
        }
        params_ = {
            "query": self.observable_name,
        }
        uri = "/api/enrichment"
        response = requests.get(self.url + uri, params=params_, headers=headers)
        response.raise_for_status()

        result = response.json()

        return result

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch(
                    "requests.get",
                    return_value=MockResponse({}, 200),
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)
