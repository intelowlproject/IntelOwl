# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import requests

from api_app.exceptions import AnalyzerRunException
from api_app.analyzers_manager import classes
from intel_owl import secrets


class GreyNoise(classes.ObservableAnalyzer):
    base_url: str = "https://api.greynoise.io"

    def set_config(self, additional_config_params):
        self.api_version = additional_config_params.get("greynoise_api_version", "v3")
        self.api_key_name = additional_config_params.get(
            "api_key_name", "GREYNOISE_API_KEY"
        )
        self.max_records_to_retrieve = int(
            additional_config_params.get("max_records_to_retrieve", 500)
        )

    def run(self):
        if self.api_version == "v1":
            url = f"{self.base_url}/v1/query/ip"
            headers = {"Content-Type": "application/x-www-form-urlencoded"}
            data = {"ip": self.observable_name}
            response = requests.post(url, data=data, headers=headers)
            response.raise_for_status()

        elif self.api_version == "v2":
            url = f"{self.base_url}/v2/noise/context/{self.observable_name}"
            api_key = secrets.get_secret(self.api_key_name)
            if not api_key:
                raise AnalyzerRunException(f"{self.api_key_name} not specified.")
            headers = {"Accept": "application/json", "key": api_key}
            response = requests.get(url, headers=headers)
            response.raise_for_status()

        elif self.api_version == "v3":
            url = f"{self.base_url}/v3/community/{self.observable_name}"
            headers = {"Accept": "application/json"}
            # optional usage of API key
            api_key = secrets.get_secret(self.api_key_name)
            if api_key:
                headers["key"] = api_key
            response = requests.get(url, headers=headers)
            if response.status_code != 404:
                response.raise_for_status()

        else:
            raise AnalyzerRunException(
                "Invalid API Version. "
                "Supported are: v1 (alpha), v2 (paid), v3 (community)"
            )

        result = response.json()
        if "records" in result:
            result["records"] = result["records"][: self.max_records_to_retrieve]

        return result
