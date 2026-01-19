# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import requests

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import AnalyzerRunException


class Ip2location(classes.ObservableAnalyzer):
    url: str = "https://api.ip2location.io/"
    _api_key_name: str
    api_version: str

    @classmethod
    def update(cls) -> bool:
        pass

    def get_response(self, payload):
        return requests.get(self.url, params=payload)

    def run(self):
        try:
            payload = {"ip": self.observable_name}

            # There are two free versions of the service:
            #    1. keyless : Requires No API key and has a daily limit of 500 queries
            #    2. keyed: Requires API key.

            if self.api_version == "keyed":
                payload["key"] = self._api_key_name

            location_info = self.get_response(payload)
            location_info.raise_for_status()

        except requests.RequestException as e:
            raise AnalyzerRunException(e)

        response = location_info.json()
        return response
