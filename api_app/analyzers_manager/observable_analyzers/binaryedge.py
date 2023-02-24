# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import requests

from api_app.analyzers_manager import classes
from api_app.exceptions import AnalyzerConfigurationException, AnalyzerRunException
from tests.mock_utils import MockResponse, if_mock_connections, patch


class BinaryEdge(classes.ObservableAnalyzer):
    base_url: str = "https://api.binaryedge.io/v2/query/"

    def set_params(self, params):
        self.__api_key = self._secrets["api_key_name"]
        if not self.__api_key:
            raise AnalyzerConfigurationException("API key is required")
        self.headers = {"X-Key": self.__api_key}

    def run(self):
        if self.observable_classification == self.ObservableTypes.IP:
            try:
                response_recent_ip_info = requests.get(
                    self.base_url + "ip/" + self.observable_name, headers=self.headers
                )
                response_recent_ip_info.raise_for_status()

                response_query_ip = requests.get(
                    self.base_url + "search?query=ip:" + self.observable_name,
                    headers=self.headers,
                )
                response_query_ip.raise_for_status()

            except requests.RequestException as e:
                raise AnalyzerRunException(e)

            results = {
                "ip_recent_report": response_recent_ip_info.json(),
                "ip_query_report": response_query_ip.json(),
            }
        elif self.observable_classification == self.ObservableTypes.DOMAIN:
            try:
                response_domain_report = requests.get(
                    self.base_url + "domains/subdomain/" + self.observable_name,
                    headers=self.headers,
                )
                results = response_domain_report.json()
            except requests.RequestException as e:
                raise AnalyzerRunException(e)
        return results

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
