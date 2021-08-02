# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import requests

from api_app.exceptions import AnalyzerRunException
from api_app.analyzers_manager import classes


class Onyphe(classes.ObservableAnalyzer):
    base_url: str = "https://www.onyphe.io/api/v2/summary/"

    def set_params(self, params):
        self.__api_key = self._secrets["api_key_name"]

    def run(self):
        headers = {
            "Authorization": f"apikey {self.__api_key}",
            "Content-Type": "application/json",
        }
        obs_clsfn = self.observable_classification

        if obs_clsfn == self.ObservableTypes.DOMAIN:
            uri = f"domain/{self.observable_name}"
        elif obs_clsfn == self.ObservableTypes.IP:
            uri = f"ip/{self.observable_name}"
        elif obs_clsfn == self.ObservableTypes.URL:
            uri = f"hostname/{self.observable_name}"
        else:
            raise AnalyzerRunException(
                f"not supported observable type {obs_clsfn}."
                " Supported are: ip, domain and url."
            )

        try:
            response = requests.get(self.base_url + uri, headers=headers)
            response.raise_for_status()
        except requests.RequestException as e:
            raise AnalyzerRunException(e)

        return response.json()
