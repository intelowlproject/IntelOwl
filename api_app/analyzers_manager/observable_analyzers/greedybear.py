# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import requests

from api_app.analyzers_manager.classes import ObservableAnalyzer
from tests.mock_utils import MockResponse, if_mock_connections, patch


class GreedyBear(ObservableAnalyzer):
    def set_params(self, params):
        self.__api_key = self._secrets["api_key_name"]
        self.url = params.get("url", "https://greedybear.honeynet.org/api/enrichment")

    def run(self):
        headers = {"Key": self.__api_key, "Accept": "application/json"}
        params_ = {
            "ipAddress": self.observable_name,
        }
        response = requests.get(self.url, params=params_, headers=headers)
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
