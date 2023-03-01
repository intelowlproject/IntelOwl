# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import requests

from api_app.analyzers_manager import classes
from tests.mock_utils import MockResponse, if_mock_connections, patch


class Hunter_Lo(classes.ObservableAnalyzer):
    base_url: str = "https://api.hunter.io/v2/domain-search?"

    def set_params(self, params):
        self.__api_key = self._secrets["api_key_name"]

    def run(self):
        url = f"{self.base_url}domain={self.observable_name}&api_key={self.__api_key}"
        response = requests.get(url)
        response.raise_for_status()

        return response.json()

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
