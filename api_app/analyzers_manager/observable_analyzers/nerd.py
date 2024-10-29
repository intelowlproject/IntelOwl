# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import requests
from requests.exceptions import HTTPError

from api_app.analyzers_manager.classes import ObservableAnalyzer
from api_app.analyzers_manager.exceptions import (
    AnalyzerConfigurationException,
    AnalyzerRunException,
)
from tests.mock_utils import MockUpResponse, if_mock_connections, patch


class NERD(ObservableAnalyzer):
    url: str = "https://nerd.cesnet.cz/nerd/api/v1"

    _api_key_name: str
    nerd_analysis: str

    def run(self):
        match self.nerd_analysis:
            case "basic":
                headers = {
                    "Authorization": self._api_key_name,
                    "Accept": "application/json",
                }
                uri = f"/ip/{self.observable_name}"
            case "full":
                headers = {
                    "Authorization": self._api_key_name,
                    "Accept": "application/json",
                }
                uri = f"/ip/{self.observable_name}/full"
            case "rep":
                headers = {
                    "Authorization": self._api_key_name,
                    "Accept": "application/json",
                }
                uri = f"/ip/{self.observable_name}/rep"
            case "fmp":
                headers = {
                    "Authorization": self._api_key_name,
                    "Accept": "application/json",
                }
                uri = f"/ip/{self.observable_name}/fmp"
            case _:
                raise AnalyzerConfigurationException(
                    f"analysis type: '{self.nerd_analysis}' not supported."
                    "Supported are: 'basic', 'full', 'rep', 'fmp'."
                )

        try:
            response = requests.get(self.url + uri, headers=headers)
            response.raise_for_status()
            result = response.json()
        except requests.RequestException as e:
            if (
                isinstance(e, HTTPError)
                and e.response.status_code == 404
                and "NOT FOUND" in str(e)
            ):
                result = {"status": "NO DATA"}
            else:
                raise AnalyzerRunException(e)

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
