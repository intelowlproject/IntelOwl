# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import requests

from api_app.analyzers_manager import classes
from api_app.exceptions import AnalyzerConfigurationException, AnalyzerRunException
from tests.mock_utils import MockResponse, if_mock_connections, patch


class ZoomEye(classes.ObservableAnalyzer):
    base_url: str = "https://api.zoomeye.org/"

    def set_params(self, params):
        self.search_type = params.get("search_type", "host")
        self.query = params.get("query", "")
        self.page = params.get("page", 1)
        self.facets = params.get("facets", "")
        self.history = params.get("history", True)
        self.__api_key = self._secrets["api_key_name"]

    def __build_zoomeye_url(self):
        if self.observable_classification == self.ObservableTypes.IP:
            self.query += f" ip:{self.observable_name}"
        else:
            self.query += f" hostname:{self.observable_name}"
            self.search_type = "host"

        if self.search_type in ["host", "web"]:
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
                f"search type: '{self.search_type}' not supported."
                "Supported are: 'host', 'web', 'both'"
            )

    def run(self):
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

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch(
                    "requests.get",
                    return_value=MockResponse({}, 200),
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)
