# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import requests

from api_app.analyzers_manager.classes import ObservableAnalyzer
from tests.mock_utils import MockUpResponse, if_mock_connections, patch
from api_app.analyzers_manager.exceptions import (
    AnalyzerConfigurationException,
    AnalyzerRunException,
)

class DShield(ObservableAnalyzer):
    url: str = "https://isc.sans.edu/api"

    # _api_key_name: str
    dshield_analysis: str

    def run(self):
        if self.dshield_analysis == "ip":
            # headers = {"Authorization": self._api_key_name, "Accept": "application/json"}
            uri = f"/ip/{self.observable_name}?json"
        elif self.dshield_analysis == "ipdetails":
            # headers = {"Authorization": self._api_key_name, "Accept": "application/json"}
            uri = f"/ipdetails/{self.observable_name}?json"
        else:
            raise AnalyzerConfigurationException(
                f"analysis type: '{self.dshield_analysis}' not supported."
                "Supported are: 'ip', 'ipdetails'."
            )

        try:
            # response = requests.get(self.url + uri, headers=headers)
            response = requests.get(self.url + uri)
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
                    return_value=MockUpResponse({}, 200),
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)
