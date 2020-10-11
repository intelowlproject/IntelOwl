import requests

from api_app.exceptions import AnalyzerRunException
from api_app.script_analyzers import classes


class Threatminer(classes.ObservableAnalyzer):
    base_url = "https://api.threatminer.org/v2/"

    def set_config(self, additional_config_params):
        self.rt_value = additional_config_params.get("rt_value", "")

    def run(self):
        params = {"q": self.observable_name}
        if self.rt_value:
            params["rt"] = self.rt_value

        if self.observable_classification == "domain":
            uri = "domain.php"
        elif self.observable_classification == "ip":
            uri = "host.php"
        else:
            raise AnalyzerRunException(
                f"not supported observable type {self.observable_classification}. "
                "Supported are IP and Domain"
            )

        try:
            response = requests.get(self.base_url + uri, params=params)
            response.raise_for_status()
        except requests.RequestException as e:
            raise AnalyzerRunException(e)

        return response.json()
