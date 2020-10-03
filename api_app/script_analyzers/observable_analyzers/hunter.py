import requests

from api_app.exceptions import AnalyzerRunException
from api_app.script_analyzers import classes
from intel_owl import secrets


class Hunter(classes.ObservableAnalyzer):
    base_url: str = "https://api.hunter.io/v2/domain-search?"

    def set_config(self, additional_config_params):
        self.api_key_name = additional_config_params.get(
            "api_key_name", "HUNTER_API_KEY"
        )

    def run(self):
        api_key = secrets.get_secret(self.api_key_name)
        if not api_key:
            raise AnalyzerRunException(
                f"no API Key retrieved with name: {self.api_key_name}"
            )

        url = f"{self.base_url}domain={self.observable_name}&api_key={api_key}"
        response = requests.get(url)
        response.raise_for_status()

        return response.json()
