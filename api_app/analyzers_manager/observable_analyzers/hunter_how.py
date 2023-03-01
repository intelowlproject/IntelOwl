# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import base64

import requests

from api_app.analyzers_manager import classes
from api_app.exceptions import AnalyzerConfigurationException, AnalyzerRunException
from tests.mock_utils import MockResponse, if_mock_connections, patch


class Hunter_How(classes.ObservableAnalyzer):
    base_url: str = "https://api.hunter.how/search"

    def set_params(self, params):
        self.__api_key = self._secrets["api_key_name"]
        self.base_url = "https://api.hunter.how/search"
        if not self.__api_key:
            raise AnalyzerConfigurationException("API key is required")
        if self.observable_classification == self.ObservableTypes.IP:
            self.query = f'ip="{self.observable_name}"'
        elif self.observable_classification == self.ObservableTypes.DOMAIN:
            self.query = f'domain="{self.observable_name}"'
        self.encoded_query = base64.urlsafe_b64encode(
            self.query.encode("utf-8")
        ).decode("ascii")
        self.page = params.get("page")
        self.page_size = params.get("page_size")
        self.start_time = params.get("start_time", "")
        self.end_time = params.get("end_time", "")

    def run(self):
        try:
            api_url = f"?api-key={self.__api_key}"
            query_url = f"&query={self.encoded_query}"
            page_url = f"&page={self.page}&page_size={self.page_size}"
            time_url = f"&start_time={self.start_time}&end_time={self.end_time}"
            params_url = api_url + query_url + page_url + time_url

            response_ip = requests.get(self.base_url + params_url)
            response_ip.raise_for_status()

        except requests.RequestException as e:
            raise AnalyzerRunException(e)

        return response_ip.json()

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
