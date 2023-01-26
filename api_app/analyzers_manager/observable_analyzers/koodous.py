# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import requests

from api_app.analyzers_manager import classes
from api_app.exceptions import AnalyzerRunException
from tests.mock_utils import MockResponse, if_mock_connections, patch


class Koodous(classes.ObservableAnalyzer):
    base_url: str = "https://developer.koodous.com/apks/"

    def set_params(self, params):
        self.__api_key = self._secrets["api_key_name"]
        self.query_analysis = params.get("query_analysis", "")

    def run(self):
        if self.query_analysis is None:
            try:
                response = requests.request(
                    "GET",
                    self.base_url + self.observable_name,
                    headers={"Authorization": f"Token {self.__api_key}"},
                    data={},
                )
                response.raise_for_status()
            except requests.RequestException as e:
                raise AnalyzerRunException(e)

        if self.query_analysis is not None:
            try:
                response = requests.request(
                    "GET",
                    self.base_url + self.observable_name + "/" + self.query_analysis,
                    headers={"Authorization": f"Token {self.__api_key}"},
                    data={},
                )
                response.raise_for_status()
            except requests.RequestException as e:
                raise AnalyzerRunException(e)

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
