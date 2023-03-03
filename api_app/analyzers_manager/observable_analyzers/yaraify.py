# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import requests

from api_app.analyzers_manager.classes import ObservableAnalyzer
from api_app.analyzers_manager.exceptions import (
    AnalyzerConfigurationException,
    AnalyzerRunException,
)
from tests.mock_utils import MockResponse, if_mock_connections, patch


class YARAify(ObservableAnalyzer):
    url: str = "https://yaraify-api.abuse.ch/api/v1/"

    query: str
    result_max: int
    _api_key_name: str

    def run(self):
        data = {"search_term": self.observable_name, "query": self.query}

        if self.observable_classification == self.ObservableTypes.GENERIC:
            data["result_max"] = self.result_max
        else:
            if not hasattr(self, "_api_key_name"):
                raise AnalyzerConfigurationException("Api key is missing")
            data["malpedia-token"] = self._api_key_name

        try:
            response = requests.post(self.url, json=data)
            response.raise_for_status()
        except requests.RequestException as e:
            raise AnalyzerRunException(e)

        result = response.json()
        return result

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch(
                    "requests.post",
                    return_value=MockResponse({}, 200),
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)
