import requests

from api_app.exceptions import AnalyzerRunException
from api_app.script_analyzers import classes
from intel_owl import secrets


class HoneyDB(classes.ObservableAnalyzer):
    base_url = "https://honeydb.io/api"

    def set_config(self, additional_config_params):
        api_key_name = additional_config_params.get("api_key_name", "HONEYDB_API_KEY")
        api_id_name = additional_config_params.get("api_id_name", "HONEYDB_API_ID")
        self.analysis_type = additional_config_params.get(
            "honeydb_analysis", "ip_query"
        )
        self.__api_key = secrets.get_secret(api_key_name)
        self.__api_id = secrets.get_secret(api_id_name)

    def run(self):
        if not self.__api_key:
            raise AnalyzerRunException("No HoneyDB API Key retrieved")
        if not self.__api_id:
            raise AnalyzerRunException("No HoneyDB API ID retrieved")
        headers = {"X-HoneyDb-ApiKey": self.__api_key, "X-HoneyDb-ApiId": self.__api_id}

        if self.analysis_type == "scan_twitter":
            url = f"{self.base_url}/twitter-threat-feed/{self.observable_name}"
        elif self.analysis_type == "ip_query":
            url = f"{self.base_url}/netinfo/lookup/{self.observable_name}"
        else:
            raise AnalyzerRunException(
                """invalid analyzer name specified.
                 Supported: HONEYDB_Scan_Twitter, HONEYDB_Get"""
            )

        response = requests.get(url, headers=headers)
        response.raise_for_status()

        result = response.json()
        return result
