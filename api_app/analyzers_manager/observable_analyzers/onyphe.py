# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import requests

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from api_app.choices import Classification


class Onyphe(classes.ObservableAnalyzer):
    url: str = "https://www.onyphe.io/api/v2/summary/"

    _api_key_name: str

    @classmethod
    def update(cls) -> bool:
        pass

    def run(self):
        headers = {
            "Authorization": f"apikey {self._api_key_name}",
            "Content-Type": "application/json",
        }
        obs_clsfn = self.observable_classification

        if obs_clsfn == Classification.DOMAIN:
            uri = f"domain/{self.observable_name}"
        elif obs_clsfn == Classification.IP:
            uri = f"ip/{self.observable_name}"
        elif obs_clsfn == Classification.URL:
            uri = f"hostname/{self.observable_name}"
        else:
            raise AnalyzerRunException(
                f"not supported observable type {obs_clsfn}. Supported are: ip, domain and url."
            )

        try:
            response = requests.get(self.url + uri, headers=headers)
            response.raise_for_status()
        except requests.RequestException as e:
            raise AnalyzerRunException(e)

        return response.json()
