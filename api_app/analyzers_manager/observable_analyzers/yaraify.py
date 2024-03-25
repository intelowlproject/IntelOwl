# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import requests

from api_app.analyzers_manager.classes import ObservableAnalyzer
from tests.mock_utils import MockUpResponse, if_mock_connections, patch


class YARAify(ObservableAnalyzer):
    url: str = "https://yaraify-api.abuse.ch/api/v1/"

    query: str
    result_max: int
    _api_key_name: str

    def run(self):
        data = {"search_term": self.observable_name, "query": self.query}

        if self.observable_classification == self.ObservableTypes.GENERIC:
            data["result_max"] = self.result_max

        if getattr(self, "_api_key_name", None):
            data["malpedia-token"] = self._api_key_name

        response = requests.post(self.url, json=data)
        response.raise_for_status()

        result = response.json()
        return result

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch(
                    "requests.post",
                    return_value=MockUpResponse({}, 200),
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)
