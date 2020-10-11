import requests
from urllib.parse import urlparse

from api_app.script_analyzers import classes


class Tranco(classes.ObservableAnalyzer):
    base_url: str = "https://tranco-list.eu/api/ranks/domain/"

    def run(self):
        observable_to_analyze = self.observable_name
        if self.observable_classification == "url":
            observable_to_analyze = urlparse(self.observable_name).hostname

        url = self.base_url + observable_to_analyze
        response = requests.get(url)
        response.raise_for_status()

        return response.json()
