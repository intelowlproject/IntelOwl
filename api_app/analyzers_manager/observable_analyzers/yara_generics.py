# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import json
import logging

import requests

from api_app.analyzers_manager.classes import ObservableAnalyzer
from api_app.exceptions import AnalyzerRunException
from tests.mock_utils import MockResponse, if_mock_connections, patch


class YaraGenerics(ObservableAnalyzer):
    def set_params(self, params):
        self.base_url: str = "https://yaraify-api.abuse.ch/api/v1/"
        self.query = params.get("query", "get_yara")
        self.result_max = params.get("result_max", "25")

    def run(self):
        self.search_term = self.observable_name
        data_ = {
            "query": self.query,
            "search_term": self.search_term,
            "result_max": self.result_max,
        }

        json_data = json.dumps(data_)

        try:
            response = requests.post(self.base_url, data=json_data)
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
