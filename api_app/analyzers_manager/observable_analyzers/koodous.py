# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import requests

from api_app.analyzers_manager import classes
from api_app.exceptions import AnalyzerRunException
from tests.mock_utils import MockResponse, if_mock_connections, patch


class Koodous(classes.ObservableAnalyzer):
    base_url: str = "https://developer.koodous.com/apks/"
    query_analysis = "/analysis"

    def set_params(self, params):
        self.__api_key = self._secrets["api_key_name"]

    def get_response(self, url):
        return requests.request(
            "GET",
            url,
            headers={"Authorization": f"Token {self.__api_key}"},
            data={},
        )

    def run(self):
        try:
            common_url = self.base_url + self.observable_name

            response_first = self.get_response(common_url)
            response_first.raise_for_status()

            response_second = self.get_response(common_url + self.query_analysis)
            response_second.raise_for_status()

        except requests.RequestException as e:
            raise AnalyzerRunException(e)

        response = {
            "first_query": response_first.json(),
            "second_query": response_second.json(),
        }

        return response

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
