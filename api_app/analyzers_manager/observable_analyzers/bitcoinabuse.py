# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import requests

from api_app.analyzers_manager import classes


class BitcoinAbuseAPI(classes.ObservableAnalyzer):
    url: str = "https://www.bitcoinabuse.com/api/reports/check"

    _api_key_name: str

    def run(self):
        params = {"address": self.observable_name, "api_token": self._api_key_name}

        response = requests.get(self.url, params=params)
        response.raise_for_status()

        return response.json()
