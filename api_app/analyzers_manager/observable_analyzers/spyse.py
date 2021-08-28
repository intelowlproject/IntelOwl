# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import requests

from api_app.exceptions import AnalyzerRunException, AnalyzerConfigurationException
from api_app.analyzers_manager import classes

from tests.mock_utils import if_mock_connections, patch, MockResponse


class Spyse(classes.ObservableAnalyzer):
    base_url: str = "https://api.spyse.com/v4/data/"

    def set_params(self, params):
        self.analysis_type = params.get("spyse_analysis", "search")
        self.__api_key = self._secrets["api_key_name"]

    def run(self):
        if self.analysis_type == "search":
            params = {"key": self.__api_key, "minify": True}


        if self.observable_classification == self.ObservableTypes.DOMAIN:
            uri = f"domain/{self.observable_name}"
        elif self.observable_classification == self.ObservableTypes.IP:
            uri = f"ip/{self.observable_name}"
        elif self.observable_classification == self.ObservableTypes.GENERIC:
            uri = f"email/{self.observable_name}"
        else:
            raise AnalyzerRunException(
                f"not supported observable type {self.observable_classification}. "
                "Supported are IP, Domain and Generic"
            )


        try:
            response = requests.get(self.base_url + uri, params=params)
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
