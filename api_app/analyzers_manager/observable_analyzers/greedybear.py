# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import requests

from api_app.analyzers_manager.classes import ObservableAnalyzer
from tests.mock_utils import MockUpResponse, if_mock_connections, patch


class GreedyBear(ObservableAnalyzer):
    _api_key_name: str
    url: str

    def run(self):
        headers = {
            "Authorization": "Token " + self._api_key_name,
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
                    return_value=MockUpResponse({}, 200),
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)
