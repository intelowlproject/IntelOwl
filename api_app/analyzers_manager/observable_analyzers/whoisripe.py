# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import requests

from api_app.analyzers_manager import classes


class WhoIsRipeAPI(classes.ObservableAnalyzer):
    url: str = "https://rest.db.ripe.net/search.json"

    def run(self):
        params = {"query-string": self.observable_name}

        response = requests.get(self.url, params=params)
        response.raise_for_status()

        return response.json()
