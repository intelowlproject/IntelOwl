import requests
from requests.auth import HTTPBasicAuth
from urllib.parse import quote_plus

from api_app.exceptions import AnalyzerRunException, AnalyzerConfigurationException
from api_app.script_analyzers import classes
from intel_owl import secrets


class XForce(classes.ObservableAnalyzer):
    base_url: str = "https://api.xforce.ibmcloud.com"

    def set_config(self, additional_config_params):
        self.api_key_name = additional_config_params.get("api_key_name", "XFORCE_KEY")
        self.api_password_name = additional_config_params.get(
            "api_password_name", "XFORCE_PASSWORD"
        )
        self.__api_key = secrets.get_secret(self.api_key_name)
        self.__api_password = secrets.get_secret(self.api_password_name)

    def run(self):
        if not self.__api_key:
            raise AnalyzerConfigurationException(
                f"No API key retrieved with name: {self.api_key_name}."
            )
        if not self.__api_password:
            raise AnalyzerConfigurationException(
                f"No API password retrieved with name: {self.api_password_name}."
            )

        auth = HTTPBasicAuth(self.__api_key, self.__api_password)

        endpoints = self._get_endpoints()
        result = {}
        for endpoint in endpoints:
            try:
                if self.observable_classification == "url":
                    observable_to_check = quote_plus(self.observable_name)
                else:
                    observable_to_check = self.observable_name
                url = f"{self.base_url}/{endpoint}/{observable_to_check}"
                response = requests.get(url, auth=auth)
                response.raise_for_status()
            except requests.RequestException as e:
                raise AnalyzerRunException(e)

            result[endpoint] = response.json()
        return result

    def _get_endpoints(self):
        """Return API endpoints for observable type

        :return: API endpoints
        :rtype: list
        """

        if self.observable_classification == "ip":
            endpoints = ["ipr", "ipr/history", "ipr/malware"]
        elif self.observable_classification == "hash":
            endpoints = ["malware"]
        elif self.observable_classification == "url":
            endpoints = ["url", "url/history", "url/malware"]
        else:
            raise AnalyzerRunException(
                f"{self.observable_classification} not supported"
            )

        return endpoints
