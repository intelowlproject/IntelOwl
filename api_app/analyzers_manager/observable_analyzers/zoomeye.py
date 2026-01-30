# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import requests

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import (
    AnalyzerConfigurationException,
    AnalyzerRunException,
)
from api_app.choices import Classification


class ZoomEye(classes.ObservableAnalyzer):
    url: str = "https://api.zoomeye.org/"

    search_type: str
    query: str
    page: int
    facets: str
    history: bool
    _api_key_name: str

    @classmethod
    def update(cls) -> bool:
        pass

    def __build_zoomeye_url(self):
        if self.observable_classification == Classification.IP:
            self.query += f" ip:{self.observable_name}"
        else:
            self.query += f" hostname:{self.observable_name}"
            self.search_type = "host"

        if self.search_type in ["host", "web"]:
            self.final_url = self.url + self.search_type + "/search?query="
            self.final_url += self.query

            if self.page:
                self.final_url += f"&page={self.page}"

            if self.facets:
                self.final_url += f"&facet={','.join(self.facets)}"

        elif self.search_type == "both":
            self.final_url = self.url + "both/search?"
            if self.history:
                self.final_url += f"history={self.history}&"
            self.final_url += f"ip={self.observable_name}"
        else:
            raise AnalyzerConfigurationException(
                f"search type: '{self.search_type}' not supported. Supported are: 'host', 'web', 'both'"
            )

    def run(self):
        self.__build_zoomeye_url()

        try:
            response = requests.get(self.final_url, headers={"API-KEY": self._api_key_name})
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
