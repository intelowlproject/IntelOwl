# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import requests

from api_app.analyzers_manager.classes import ObservableAnalyzer
from api_app.exceptions import AnalyzerRunException
from tests.mock_utils import MockResponse, if_mock_connections, patch


class YARAify(ObservableAnalyzer):
    def set_params(self, params):
        self.url: str = "https://yaraify-api.abuse.ch/api/v1/"
        self.search_term = self.observable_name

        self.query: str = "lookup_hash"

        if self.observable_classification == self.ObservableTypes.GENERIC:
            self.query: str = params.get("query", "get_yara")
            self.result_max: int = params.get("result_max", 25)
        else:
            self.__api_key = self._secrets["api_key_name"]

    def run(self):
        data = {"search_term": self.search_term, "query": self.query}

        if self.observable_classification == self.ObservableTypes.GENERIC:
            data["result_max"] = self.result_max
        else:
            data["malpedia-token"] = self.__api_key

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
