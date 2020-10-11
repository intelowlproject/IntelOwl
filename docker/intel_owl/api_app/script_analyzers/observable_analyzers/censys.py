import requests

from api_app.exceptions import AnalyzerRunException
from api_app.script_analyzers import classes
from intel_owl import secrets


class Censys(classes.ObservableAnalyzer):
    base_url = "https://www.censys.io/api/v1"

    def set_config(self, additional_config_params):
        self.analysis_type = additional_config_params.get("censys_analysis", "search")
        api_id_name = additional_config_params.get("api_id_name", "CENSYS_API_ID")
        api_secret_name = additional_config_params.get(
            "api_secret_name", "CENSYS_API_SECRET"
        )
        self.__api_id = secrets.get_secret(api_id_name)
        self.__api_secret = secrets.get_secret(api_secret_name)

    def run(self):
        if not (self.__api_id and self.__api_secret):
            raise AnalyzerRunException("no api credentials retrieved")

        if self.analysis_type == "search":
            uri = f"/view/ipv4/{self.observable_name}"
        else:
            raise AnalyzerRunException(
                f"not supported observable type {self.observable_classification}."
                "Supported is IP"
            )
        try:
            response = requests.get(
                self.base_url + uri, auth=(self.__api_id, self.__api_secret)
            )
            response.raise_for_status()
        except requests.RequestException as e:
            raise AnalyzerRunException(e)

        return response.json()
