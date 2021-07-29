# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import requests

from api_app.exceptions import AnalyzerRunException
from api_app.analyzers_manager import classes


class Threatminer(classes.ObservableAnalyzer):
    base_url = "https://api.threatminer.org/v2/"

    def set_params(self, params):
        self.rt_value = params.get("rt_value", "")

    def run(self):
        params = {"q": self.observable_name}
        if self.rt_value:
            params["rt"] = self.rt_value

        if self.observable_classification == self.ObservableTypes.DOMAIN:
            uri = "domain.php"
        elif self.observable_classification == self.ObservableTypes.IP:
            uri = "host.php"
        else:
            raise AnalyzerRunException(
                f"not supported observable type {self.observable_classification}. "
                "Supported are IP and Domain"
            )

        try:
            response = requests.get(self.base_url + uri, params=params)
            response.raise_for_status()
        except requests.RequestException as e:
            raise AnalyzerRunException(e)

        return response.json()
