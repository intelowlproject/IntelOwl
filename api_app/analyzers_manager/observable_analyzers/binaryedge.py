# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
from typing import Dict

import requests

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from tests.mock_utils import MockUpResponse, if_mock_connections, patch


class BinaryEdge(classes.ObservableAnalyzer):
    url: str = "https://api.binaryedge.io/v2/query/"

    _api_key_name: str

    @classmethod
    def update(cls) -> bool:
        pass

    def config(self, runtime_configuration: Dict):
        super().config(runtime_configuration)
        self.headers = {"X-Key": self._api_key_name}

    def run(self):
        results = {}
        if self.observable_classification == self.ObservableTypes.IP:
            try:
                response_recent_ip_info = requests.get(
                    self.url + "ip/" + self.observable_name, headers=self.headers
                )
                response_recent_ip_info.raise_for_status()

                response_query_ip = requests.get(
                    self.url + "search?query=ip:" + self.observable_name,
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
                    self.url + "domains/subdomain/" + self.observable_name,
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
                    return_value=MockUpResponse({}, 200),
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)
