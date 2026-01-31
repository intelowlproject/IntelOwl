# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import requests
from requests.exceptions import HTTPError

from api_app.analyzers_manager.classes import ObservableAnalyzer
from api_app.analyzers_manager.exceptions import (
    AnalyzerConfigurationException,
    AnalyzerRunException,
)


class NERD(ObservableAnalyzer):
    url: str = "https://nerd.cesnet.cz/nerd/api/v1"

    _api_key_name: str
    nerd_analysis: str

    def update(self) -> bool:
        pass

    def run(self):
        base_uri = f"/ip/{self.observable_name}"
        headers = {
            "Authorization": self._api_key_name,
            "Accept": "application/json",
        }
        match self.nerd_analysis:
            case "basic":
                uri = base_uri
            case "full" | "rep" | "fmp" as option:
                uri = f"{base_uri}/{option}"
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
            if isinstance(e, HTTPError) and e.response.status_code == 404 and "NOT FOUND" in str(e):
                result = {"status": "NO DATA"}
            else:
                raise AnalyzerRunException(e)

        return result
