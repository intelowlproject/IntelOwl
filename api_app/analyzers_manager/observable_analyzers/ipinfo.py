# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import requests

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import AnalyzerRunException


class IPInfo(classes.ObservableAnalyzer):
    url: str = "https://ipinfo.io/"

    _api_key_name: str

    @classmethod
    def update(cls) -> bool:
        pass

    def run(self):
        try:
            response = requests.get(
                self.url + self.observable_name,
                params={"token": self._api_key_name},
            )
            response.raise_for_status()
        except requests.RequestException as e:
            raise AnalyzerRunException(e)

        result = response.json()
        return result
