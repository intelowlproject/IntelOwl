import requests

from api_app.exceptions import AnalyzerRunException
from api_app.script_analyzers import classes
from intel_owl import secrets


class Onyphe(classes.ObservableAnalyzer):
    base_url: str = "https://www.onyphe.io/api/v2/summary/"

    def set_config(self, additional_config_params):
        self.api_key_name = additional_config_params.get("api_key_name", "ONYPHE_KEY")

    def run(self):
        api_key = secrets.get_secret(self.api_key_name)
        if not api_key:
            raise AnalyzerRunException(
                f"no API key retrieved with name: '{self.api_key_name}'"
            )

        headers = {
            "Authorization": f"apikey {api_key}",
            "Content-Type": "application/json",
        }
        obs_clsfn = self.observable_classification

        if obs_clsfn == "domain":
            uri = f"domain/{self.observable_name}"
        elif obs_clsfn == "ip":
            uri = f"ip/{self.observable_name}"
        elif obs_clsfn == "url":
            uri = f"hostname/{self.observable_name}"
        else:
            raise AnalyzerRunException(
                f"not supported observable type {obs_clsfn}."
                " Supported are: ip, domain and url."
            )

        try:
            response = requests.get(self.base_url + uri, headers=headers)
            response.raise_for_status()
        except requests.RequestException as e:
            raise AnalyzerRunException(e)

        return response.json()
