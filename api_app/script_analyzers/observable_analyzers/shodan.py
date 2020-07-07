import requests

from api_app.exceptions import AnalyzerRunException
from api_app.script_analyzers import classes
from intel_owl import secrets


class Shodan(classes.ObservableAnalyzer):
    base_url: str = "https://api.shodan.io/"

    def set_config(self, additional_config_params):
        self.analysis_type = additional_config_params.get("shodan_analysis", "search")
        api_key_name = additional_config_params.get("api_key_name", "SHODAN_KEY")
        self.__api_key = secrets.get_secret(api_key_name)

    def run(self):
        if not self.__api_key:
            raise AnalyzerRunException("no api key retrieved")

        if self.analysis_type == "search":
            params = {"key": self.__api_key, "minify": True}
            uri = f"shodan/host/{self.observable_name}"
        elif self.analysis_type == "honeyscore":
            params = {
                "key": self.__api_key,
            }
            uri = f"labs/honeyscore/{self.observable_name}"
        else:
            raise AnalyzerRunException(
                f"not supported observable type {self.observable_classification}."
                "Supported is IP"
            )

        try:
            response = requests.get(self.base_url + uri, params=params)
            response.raise_for_status()
        except requests.RequestException as e:
            raise AnalyzerRunException(e)

        return response.json()
