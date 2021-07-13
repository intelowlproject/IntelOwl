# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import requests
from urllib.parse import urlparse

from api_app.analyzers_manager import classes


class Tranco(classes.ObservableAnalyzer):
    base_url: str = "https://tranco-list.eu/api/ranks/domain/"

    def run(self):
        observable_to_analyze = self.observable_name
        if self.observable_classification == self._serializer.ObservableTypes.URL.value:
            observable_to_analyze = urlparse(self.observable_name).hostname

        url = self.base_url + observable_to_analyze
        response = requests.get(url)
        response.raise_for_status()

        return response.json()
