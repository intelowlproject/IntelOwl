import requests

from api_app.exceptions import AnalyzerRunException
from api_app.script_analyzers import classes


class MB_GET(classes.ObservableAnalyzer):
    url: str = "https://mb-api.abuse.ch/api/v1/"

    def run(self):
        if self.observable_classification != "hash":
            raise AnalyzerRunException(
                f"not supported observable type {self.observable_classification}."
                f" Supported: hash only"
            )

        post_data = {"query": "get_info", "hash": self.observable_name}

        response = requests.post(self.url, data=post_data)
        response.raise_for_status()

        return response.json()
