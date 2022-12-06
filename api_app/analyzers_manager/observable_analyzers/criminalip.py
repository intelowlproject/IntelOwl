# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import requests

from api_app.analyzers_manager import classes
from api_app.exceptions import AnalyzerConfigurationException, AnalyzerRunException
from tests.mock_utils import MockResponse, if_mock_connections, patch


class Shodan(classes.ObservableAnalyzer):
    base_url: str = "https://api.criminalip.io/v1"

    def set_params(self, params):
        self.analysis_type = params.get("criminalip_analysis", "search")
        self.__api_key = self._secrets["api_key_name"]

    def run(self):
        try:
            if self.analysis_type == "search":
                params = {"x-api-key": self.__api_key}
                uri = f"ip/data?ip={self.observable_name}"

                response = requests.get(self.base_url + uri, headers=params)
                response.raise_for_status()
            elif self.analysis_type == "domain":
                params = {
                    "x-api-key": self.__api_key,
                }
                uri = f"domain/scan/"
                payload={"query":{self.observable_name}}
                response = requests.post(self.base_url + uri, headers=params, data=payload)
                response.raise_for_status()

            else:
                raise AnalyzerConfigurationException(
                    f"analysis type: '{self.analysis_type}' not supported."
                    "Supported are: 'search', 'domain'."
                )

        except requests.RequestException as e:
            raise AnalyzerRunException(e)

        result = response.json()
        if self.analysis_type == "domain":
            return {"domain": result}
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
