# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import requests

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import AnalyzerRunException


class Ip2whois(classes.ObservableAnalyzer):
    url: str = "https://api.ip2whois.com/v2"
    _api_key_name: str

    def update(self):
        pass

    def get_response(self, payload):
        return requests.get(self.url, params=payload)

    def run(self):
        try:
            params = {
                "key": self._api_key_name,
                "domain": self.observable_name,
            }

            location_info = self.get_response(params)
            location_info.raise_for_status()

        except requests.RequestException as e:
            raise AnalyzerRunException(e)

        response = location_info.json()
        return response
