# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import requests

from api_app.analyzers_manager import classes
from api_app.exceptions import AnalyzerRunException
from tests.mock_utils import MockResponse, if_mock_connections, patch


class IPInfo(classes.ObservableAnalyzer):
    base_url: str = "https://ipinfo.io/"

    def set_params(self, params):
        self.__api_key = self._secrets["api_key_name"]

    def run(self):
        try:
            response = requests.get(
                self.base_url + self.observable_name,
                params={"token": self.__api_key},
            )
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
                    "requests.get",
                    return_value=MockResponse({}, 200),
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)
