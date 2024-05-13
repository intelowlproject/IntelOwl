# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import requests

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import (
    AnalyzerConfigurationException,
    AnalyzerRunException,
)
from tests.mock_utils import MockUpResponse, if_mock_connections, patch


class Shodan(classes.ObservableAnalyzer):
    url: str = "https://api.shodan.io/"

    shodan_analysis: str
    _api_key_name: str

    @classmethod
    def update(cls) -> bool:
        pass

    def run(self):
        if self.shodan_analysis == "search":
            params = {"key": self._api_key_name, "minify": True}
            uri = f"shodan/host/{self.observable_name}"
        elif self.shodan_analysis == "honeyscore":
            params = {
                "key": self._api_key_name,
            }
            uri = f"labs/honeyscore/{self.observable_name}"
        else:
            raise AnalyzerConfigurationException(
                f"analysis type: '{self.shodan_analysis}' not supported."
                "Supported are: 'search', 'honeyscore'."
            )

        try:
            response = requests.get(self.url + uri, params=params)
            response.raise_for_status()
        except requests.RequestException as e:
            raise AnalyzerRunException(e)

        result = response.json()
        if self.shodan_analysis == "honeyscore":
            return {"honeyscore": result}
        return result

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch(
                    "requests.get",
                    return_value=MockUpResponse({}, 200),
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)
