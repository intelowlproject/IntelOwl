import requests

from api_app.exceptions import AnalyzerRunException
from api_app.script_analyzers.classes import ObservableAnalyzer
from intel_owl import secrets


class AbuseIPDB(ObservableAnalyzer):
    url: str = "https://api.abuseipdb.com/api/v2/check"

    def set_config(self, additional_config_params):
        self.api_key_name = additional_config_params.get(
            "api_key_name", "ABUSEIPDB_KEY"
        )
        self.__api_key = secrets.get_secret(self.api_key_name)

    def run(self):
        if not self.__api_key:
            raise AnalyzerRunException(
                f"No API key retrieved with name: {self.api_key_name}"
            )

        headers = {"Key": self.__api_key, "Accept": "application/json"}
        params = {
            "ipAddress": self.observable_name,
            "maxAgeInDays": 180,
            "verbose": True,
        }
        response = requests.get(self.url, params=params, headers=headers)
        response.raise_for_status()

        return response.json()
