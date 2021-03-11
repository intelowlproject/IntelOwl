import requests

from api_app.exceptions import AnalyzerRunException, AnalyzerConfigurationException
from api_app.script_analyzers import classes
from intel_owl import secrets


class ThreatFox(classes.ObservableAnalyzer):
    base_url: str = "https://threatfox-api.abuse.ch/api/v1/"

    def set_config(self, additional_config_params):
        self.api_key_name = additional_config_params.get(
            "api_key_name", "THREATFOX_KEY"
        )
        self.__api_key = secrets.get_secret(self.api_key_name)

    def parse_input(self):
        fields = self.observable_name.split("&")
        args = {}
        for field in fields:
            key, value = field.split("=")
            args[key] = value
        return args

    def run(self):
        if not self.__api_key:
            raise AnalyzerConfigurationException(
                f"No API key retrieved with name: {self.api_key_name}."
            )
        args = self.parse_input()

        try:
            response = requests.post(self.base_url, json=args)
            response.raise_for_status()
        except requests.RequestException as e:
            raise AnalyzerRunException(e)

        result = response.json()
        return result
