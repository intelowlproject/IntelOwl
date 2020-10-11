import json
import requests
from urllib.parse import urlparse

from api_app.exceptions import AnalyzerRunException
from api_app.script_analyzers import classes


class Robtex(classes.ObservableAnalyzer):
    base_url = "https://freeapi.robtex.com/"

    def set_config(self, additional_config_params):
        self.analysis_type = additional_config_params.get("robtex_analysis", "ip_query")

    def run(self):
        if self.analysis_type == "ip_query":
            uri = f"ipquery/{self.observable_name}"
        elif self.analysis_type == "reverse_pdns":
            uri = f"pdns/reverse/{self.observable_name}"
        elif self.analysis_type == "forward_pdns":
            domain = self.observable_name
            if self.observable_classification == "url":
                domain = urlparse(self.observable_name).hostname
            uri = f"pdns/forward/{domain}"
        else:
            raise AnalyzerRunException(
                f"not supported analysis type {self.analysis_type}."
            )
        try:
            response = requests.get(self.base_url + uri)
            response.raise_for_status()
            result = response.text.split("\r\n")
        except requests.ConnectionError as e:
            raise AnalyzerRunException(f"Connection error: {e}")
        else:
            loaded_results = []
            for item in result:
                if len(item) > 0:
                    loaded_results.append(json.loads(item))

        return loaded_results
