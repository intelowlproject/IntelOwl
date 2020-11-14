import requests

from api_app.exceptions import AnalyzerRunException, AnalyzerConfigurationException
from api_app.script_analyzers import classes
from intel_owl import secrets


class ZoomEye(classes.ObservableAnalyzer):
    base_url: str = "https://api.zoomeye.org/"

    def set_config(self, additional_config_params):
        self.api_key_name = additional_config_params.get("api_key_name", "ZOOMEYE_KEY")
        self.search_type = additional_config_params.get("search_type", "host")
        self.query = additional_config_params.get("query", "")
        self.page = additional_config_params.get("page", 1)
        self.facets = additional_config_params.get("facets", "")
        self.history = additional_config_params.get("history", True)
        self.__api_key = secrets.get_secret(self.api_key_name)

    def __build_zoomeye_url(self):
        if self.observable_classification == "ip":
            self.query += f" ip:{self.observable_name}"
        else:
            self.query += f" hostname:{self.observable_name}"
            self.search_type = "host"

        if self.search_type == "host" or self.search_type == "web":
            self.url = self.base_url + self.search_type + "/search?query="
            self.url += self.query

            if self.page:
                self.url += f"&page={self.page}"

            if self.facets:
                self.url += f"&facet={','.join(self.facets)}"

        elif self.search_type == "both":
            self.url = self.base_url + "both/search?"
            if self.history:
                self.url += f"history={self.history}&"
            self.url += f"ip={self.observable_name}"
        else:
            raise AnalyzerConfigurationException(
                f"search type: '{self.search_type}' not suported."
                "Supported are: 'host', 'web', 'both'"
            )

    def run(self):
        if not self.__api_key:
            raise AnalyzerRunException(
                f"No API key retrieved with name: '{self.api_key_name}'"
            )

        self.__build_zoomeye_url()

        try:
            response = requests.get(self.url, headers={"API-KEY": self.__api_key})
            response.raise_for_status()
        except requests.RequestException as e:
            raise AnalyzerRunException(e)

        result = {"custom_options": {}}
        result["custom_options"]["search_type"] = self.search_type
        result["custom_options"]["query"] = self.query
        if self.page:
            result["custom_options"]["page"] = self.page
        if self.facets:
            result["custom_options"]["facet"] = self.facets
        if self.history and self.search_type == "both":
            result["custom_options"]["history"] = self.history
        result.update(response.json())

        return result
