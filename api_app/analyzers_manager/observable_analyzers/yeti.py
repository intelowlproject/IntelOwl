# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import requests

from api_app.analyzers_manager import classes
from api_app.exceptions import AnalyzerRunException
from tests.mock_utils import MockResponse, if_mock_connections, patch


class YETI(classes.ObservableAnalyzer):
    def set_params(self, params):
        self.verify_ssl = params.get("verify_ssl", True)
        self.results_count = params.get("results_count", 50)
        self.regex = params.get("regex", False)
        self.__url_name = self._secrets["url_key_name"]
        self.__api_key = self._secrets["api_key_name"]

    def run(self):
        # request payload
        payload = {
            "filter": {"value": self._job.observable_name},
            "params": {"regex": self.regex, "range": self.results_count},
        }
        headers = {"Accept": "application/json", "X-Api-Key": self.__api_key}
        if self.__url_name.endswith("/"):
            self.__url_name = self.__url_name[:-1]
        url = f"{self.__url_name}/observablesearch/"

        # search for observables
        try:
            resp = requests.post(
                url=url,
                headers=headers,
                json=payload,
                verify=self.verify_ssl,
            )
            resp.raise_for_status()
        except requests.RequestException as e:
            raise AnalyzerRunException(e)

        return resp.json()

    @classmethod
    def _monkeypatch(cls):

        patches = [
            if_mock_connections(
                patch(
                    "requests.post",
                    return_value=MockResponse([], 200),
                )
            )
        ]
        return super()._monkeypatch(patches=patches)
