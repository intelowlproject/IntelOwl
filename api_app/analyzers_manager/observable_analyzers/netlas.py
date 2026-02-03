# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
from typing import Dict

import requests

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import AnalyzerRunException


class Netlas(classes.ObservableAnalyzer):
    url: str = "https://app.netlas.io/api/whois_ip/"

    _api_key_name: str

    @classmethod
    def update(cls) -> bool:
        pass

    def config(self, runtime_configuration: Dict):
        super().config(runtime_configuration)
        self.query = self.observable_name

        self.headers = {"X-API-Key": f"{self._api_key_name}"}

        self.parameters = {"q": f"ip:{self.query}"}

    def run(self):
        try:
            response = requests.get(self.url, params=self.parameters, headers=self.headers)
            response.raise_for_status()
        except requests.RequestException as e:
            raise AnalyzerRunException(e)

        result = response.json()["items"][0]["data"]
        return result
