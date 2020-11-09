import requests

from api_app.exceptions import AnalyzerRunException, AnalyzerConfigurationException
from api_app.script_analyzers import classes
from intel_owl import secrets


class IPInfo(classes.ObservableAnalyzer):
    base_url: str = "https://ipinfo.io/"

    def set_config(self, additional_config_params):
        self.api_key_name = additional_config_params.get("api_key_name", "IPINFO_KEY")
        self.__api_key = secrets.get_secret(self.api_key_name)

    def run(self):
        if not self.__api_key:
            raise AnalyzerConfigurationException(
                f"No API key retrieved with name: {self.api_key_name}."
            )

        try:
            response = requests.get(
                self.base_url + self.observable_name,
                params={"token": self.__api_key},
            )
            response.raise_for_status()
        except requests.RequestException as e:
            raise AnalyzerRunException(e)

        result = response.json()
        return result
