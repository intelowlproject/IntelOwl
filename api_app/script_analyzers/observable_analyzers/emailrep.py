import requests

from api_app.exceptions import AnalyzerRunException
from api_app.script_analyzers import classes
from intel_owl import secrets


class EmailRep(classes.ObservableAnalyzer):
    base_url: str = "https://emailrep.io/{}"

    def set_config(self, additional_config_params):
        self.api_key_name = additional_config_params.get("api_key_name", "EMAILREP_KEY")
        self.__api_key = secrets.get_secret(self.api_key_name)

    def run(self):
        """
        API key is not mandatory, emailrep supports requests with no key:
        a valid key let you to do more requests per day.
        therefore we're not checking if a key has been configured.
        """

        headers = {
            "User-Agent": "IntelOwl v2",
            "Key": self.__api_key,
            "Accept": "application/json",
        }

        if self.observable_classification not in ["generic"]:
            raise AnalyzerRunException(
                f"not supported observable type {self.observable_classification}."
                f" Supported: generic"
            )

        url = self.base_url.format(self.observable_name)

        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()
        except requests.RequestException as e:
            raise AnalyzerRunException(e)

        return response.json()
