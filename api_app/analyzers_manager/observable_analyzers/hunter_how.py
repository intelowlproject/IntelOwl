# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import base64

import requests

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from tests.mock_utils import MockResponse, if_mock_connections, patch


class Hunter_How(classes.ObservableAnalyzer):
    base_url: str = "https://api.hunter.how/search"
    _api_key_name: str
    page: int
    page_size: int
    start_time: str
    end_time: str

    def config(self):
        super().config()
        if self.observable_classification == self.ObservableTypes.IP:
            self.query = f'ip="{self.observable_name}"'
        elif self.observable_classification == self.ObservableTypes.DOMAIN:
            self.query = f'domain="{self.observable_name}"'

        self.encoded_query = base64.urlsafe_b64encode(
            self.query.encode("utf-8")
        ).decode("ascii")
        self.parameters = {
            "api-key": self._api_key_name,
            "query": self.encoded_query,
            "page": self.page,
            "page_size": self.page_size,
            "start_time": self.start_time,
            "end_time": self.end_time,
        }

    def run(self):
        try:
            response_ip = requests.get(self.base_url, params=self.parameters)
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
                    return_value=MockResponse({"list": []}, 200),
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)
