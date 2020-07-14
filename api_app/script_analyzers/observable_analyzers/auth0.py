import requests

from api_app.exceptions import AnalyzerRunException
from api_app.script_analyzers import classes
from intel_owl import secrets


class Auth0(classes.ObservableAnalyzer):
    name: str = "Auth0"
    base_url: str = "https://signals.api.auth0.com/v2.0/ip"

    def set_config(self, additional_config_params):
        api_key_name = additional_config_params.get("api_key_name", "AUTH0_KEY")
        self.__api_key = secrets.get_secret(api_key_name)

    def run(self):
        if not self.__api_key:
            raise AnalyzerRunException("no api key retrieved")

        headers = {"X-Auth-Token": self.__api_key}
        url = f"{self.base_url}/{self.observable_name}"
        response = requests.get(url, headers=headers)
        response.raise_for_status()

        json_response = response.json()
        return json_response
