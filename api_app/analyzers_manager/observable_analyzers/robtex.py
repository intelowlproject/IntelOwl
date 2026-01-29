# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import json
from urllib.parse import urlparse

import requests

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from api_app.choices import Classification


class Robtex(classes.ObservableAnalyzer):
    url = "https://freeapi.robtex.com/"

    @classmethod
    def update(cls) -> bool:
        pass

    def run(self):
        if self.observable_classification == Classification.IP:
            uris = [
                f"ipquery/{self.observable_name}",
                f"pdns/reverse/{self.observable_name}",
            ]
        elif self.observable_classification in [
            Classification.URL,
            Classification.DOMAIN,
        ]:
            if self.observable_classification == Classification.URL:
                domain = urlparse(self.observable_name).hostname
            else:
                domain = self.observable_name
            uris = [f"pdns/forward/{domain}"]
        else:
            raise AnalyzerRunException(f"not supported analysis type {self.observable_classification}.")

        loaded_results = []
        for uri in uris:
            response = requests.get(self.url + uri)
            response.raise_for_status()
            result = response.text.split("\r\n")
            for item in result:
                if len(item) > 0:
                    loaded_results.append(json.loads(item))

        return loaded_results
