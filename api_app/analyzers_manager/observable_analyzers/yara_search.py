# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import json

import requests

from api_app.analyzers_manager.classes import ObservableAnalyzer
from tests.mock_utils import MockResponse, if_mock_connections, patch


class YaraSearch(ObservableAnalyzer):
    def set_params(self, params):
        self.base_url: str = "https://yaraify-api.abuse.ch/api/v1/"
        self.query = "lookup_hash"
        self.__api_key = self._secrets["api_key_name"]
        self.search_term = self.observable_name

    # def run(self):
    #    data_ = {
    #        'query': self.query,
    #        'search_term' : self.search_term,
    #        'malpedia-token' : self.__api_key
    #    }

    #    json_data = json.dumps(data_)
    #    response = requests.post(self.base_url, data=json_data)
    #    response.raise_for_status()
    #    result = response.json()

    #    return result

    def run(self):
        return self.before_file_scan(self.observable_name)

    def before_file_scan(self, hash):
        self.search_term = hash
        self.base_url: str = "https://yaraify-api.abuse.ch/api/v1/"
        self.query = "lookup_hash"
        self.__api_key = self._secrets["api_key_name"]

        data_ = {
            "query": self.query,
            "search_term": self.search_term,
            "malpedia-token": self.__api_key,
        }

        json_data = json.dumps(data_)
        response = requests.post(self.base_url, data=json_data)
        response.raise_for_status()
        result = response.json()

        return result

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch(
                    "requests.post",
                    return_value=MockResponse({}, 200),
                )
            )
        ]
        return super()._monkeypatch(patches=patches)
