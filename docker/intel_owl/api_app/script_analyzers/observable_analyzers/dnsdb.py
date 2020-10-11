import json
from urllib.parse import urlparse

import requests

from api_app.exceptions import AnalyzerRunException
from api_app.script_analyzers import classes
from intel_owl import secrets


class DNSdb(classes.ObservableAnalyzer):
    def set_config(self, additional_config_params):
        self.limit = additional_config_params.get("limit", 1000)
        api_key_name = additional_config_params.get("api_key_name", "DNSDB_KEY")
        self.__api_key = secrets.get_secret(api_key_name)

    def run(self):
        if not self.__api_key:
            raise AnalyzerRunException("no api key retrieved")

        if not isinstance(self.limit, int):
            raise AnalyzerRunException(
                "limit: {self.limit} ({type(self.limit)}) must be a integer"
            )

        headers = {"Accept": "application/json", "X-API-Key": self.__api_key}

        observable_to_check = self.observable_name
        # for URLs we are checking the relative domain
        if self.observable_classification == "url":
            observable_to_check = urlparse(self.observable_name).hostname

        if self.observable_classification == "ip":
            endpoint = "rdata/ip"
        elif self.observable_classification in ["domain", "url"]:
            endpoint = "rrset/name"
        else:
            raise AnalyzerRunException(
                f"{self.observable_classification} not supported"
            )

        url = f"https://api.dnsdb.info/lookup/{endpoint}/{observable_to_check}"
        params = {"limit": self.limit}
        response = requests.get(url, params=params, headers=headers)
        response.raise_for_status()
        results_list = response.text
        json_extracted_results = []
        for item in results_list.split("\n"):
            if item:
                json_extracted_results.append(json.loads(item))

        return json_extracted_results
