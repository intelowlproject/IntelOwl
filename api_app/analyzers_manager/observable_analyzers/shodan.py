# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import requests

from api_app.exceptions import AnalyzerRunException, AnalyzerConfigurationException
from api_app.analyzers_manager import classes


class Shodan(classes.ObservableAnalyzer):
    base_url: str = "https://api.shodan.io/"

    def set_params(self, params):
        self.analysis_type = params.get("shodan_analysis", "search")
        self.__api_key = self._secrets["api_key_name"]

    def run(self):
        if self.analysis_type == "search":
            params = {"key": self.__api_key, "minify": True}
            uri = f"shodan/host/{self.observable_name}"
        elif self.analysis_type == "honeyscore":
            params = {
                "key": self.__api_key,
            }
            uri = f"labs/honeyscore/{self.observable_name}"
        else:
            raise AnalyzerConfigurationException(
                f"analysis type: '{self.analysis_type}' not suported."
                "Supported are: 'search', 'honeyscore'."
            )

        try:
            response = requests.get(self.base_url + uri, params=params)
            response.raise_for_status()
        except requests.RequestException as e:
            raise AnalyzerRunException(e)

        result = response.json()
        if self.analysis_type == "honeyscore":
            return {"honeyscore": result}
        return result
