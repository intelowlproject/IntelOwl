# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import requests

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import (
    AnalyzerConfigurationException,
    AnalyzerRunException,
)
from tests.mock_utils import MockResponse, if_mock_connections, patch


class Shodan(classes.ObservableAnalyzer):
    base_url: str = "https://api.shodan.io/"

    def set_params(self, params):
        self.analysis_type = params.get("shodan_analysis", "search")
        self.__api_key = self._secrets["api_key_name"]

    def run(self):
        if self.analysis_type == "search":
            params = {"key": self.__api_key, "minify": True}
            uri = f"shodan/host/{self.observable_name}"
        elif self.analysis_type == "honeyscore":
            params = {
                "key": self.__api_key,
            }
            uri = f"labs/honeyscore/{self.observable_name}"
        else:
            raise AnalyzerConfigurationException(
                f"analysis type: '{self.analysis_type}' not supported."
                "Supported are: 'search', 'honeyscore'."
            )

        try:
            response = requests.get(self.base_url + uri, params=params)
            response.raise_for_status()
        except requests.RequestException as e:
            raise AnalyzerRunException(e)

        result = response.json()
        if self.analysis_type == "honeyscore":
            return {"honeyscore": result}
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
