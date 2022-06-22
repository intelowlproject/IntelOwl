# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.


import json
import logging

import requests

from api_app.analyzers_manager.classes import ObservableAnalyzer
from api_app.exceptions import AnalyzerRunException
from tests.mock_utils import MockResponse, if_mock_connections, patch

logger = logging.getLogger(__name__)


class YaraSearch(ObservableAnalyzer):
    def run(self):
        self.url: str = "https://yaraify-api.abuse.ch/api/v1/"
        self.query = "lookup_hash"
        self.search_term = self.observable_name

        return self.scan()

    def scan(self):
        self.__api_key = self._secrets["api_key_name"]

        data = {
            "query": self.query,
            "search_term": self.search_term,
            "malpedia-token": self.__api_key,
        }

        json_data = json.dumps(data)

        try:
            response = requests.post(self.url, data=json_data)
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
                )
            )
        ]
        return super()._monkeypatch(patches=patches)
