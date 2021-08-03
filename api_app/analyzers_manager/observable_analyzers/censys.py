# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import requests

from api_app.exceptions import AnalyzerRunException
from api_app.analyzers_manager import classes

from tests.mock_utils import if_mock_connections, patch, MockResponse


class Censys(classes.ObservableAnalyzer):
    base_url = "https://www.censys.io/api/v1"

    def set_params(self, params):
        self.analysis_type = params.get("censys_analysis", "search")
        self.__api_id = self._secrets["api_id_name"]
        self.__api_secret = self._secrets["api_secret_name"]

    def run(self):
        if self.analysis_type == "search":
            uri = f"/view/ipv4/{self.observable_name}"
        else:
            raise AnalyzerRunException(
                f"not supported observable type {self.observable_classification}."
                "Supported is IP"
            )
        try:
            response = requests.get(
                self.base_url + uri, auth=(self.__api_id, self.__api_secret)
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
