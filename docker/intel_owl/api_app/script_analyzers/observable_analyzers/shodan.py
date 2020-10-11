import requests

from api_app.exceptions import AnalyzerRunException, AnalyzerConfigurationException
from api_app.script_analyzers import classes
from intel_owl import secrets


class Shodan(classes.ObservableAnalyzer):
    base_url: str = "https://api.shodan.io/"

    def set_config(self, additional_config_params):
        self.analysis_type = additional_config_params.get("shodan_analysis", "search")
        self.api_key_name = additional_config_params.get("api_key_name", "SHODAN_KEY")
        self.__api_key = secrets.get_secret(self.api_key_name)

    def run(self):
        if not self.__api_key:
            raise AnalyzerConfigurationException(
                f"No API key retrieved with name: {self.api_key_name}."
            )

        if self.analysis_type == "search":
            params = {"key": self.__api_key, "minify": True}
            uri = f"shodan/host/{self.observable_name}"
        elif self.analysis_type == "honeyscore":
            params = {
                "key": self.__api_key,
            }
            uri = f"labs/honeyscore/{self.observable_name}"
        else:
            raise AnalyzerConfigurationException(
                f"analysis type: '{self.analysis_type}' not suported."
                "Supported are: 'search', 'honeyscore'."
            )

        try:
            response = requests.get(self.base_url + uri, params=params)
            response.raise_for_status()
        except requests.RequestException as e:
            raise AnalyzerRunException(e)

        result = response.json()
        if self.analysis_type == "honeyscore":
            return {"honeyscore": result}
        return result
