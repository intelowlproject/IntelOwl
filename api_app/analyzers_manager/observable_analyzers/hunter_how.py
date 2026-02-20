# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import base64
from typing import Dict

import requests

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from api_app.choices import Classification


class Hunter_How(classes.ObservableAnalyzer):
    url: str = "https://api.hunter.how/search"
    _api_key_name: str
    page: int
    page_size: int
    start_time: str
    end_time: str

    def config(self, runtime_configuration: Dict):
        super().config(runtime_configuration)
        if self.observable_classification == Classification.IP:
            self.query = f'ip="{self.observable_name}"'
        elif self.observable_classification == Classification.DOMAIN:
            self.query = f'domain="{self.observable_name}"'

        self.encoded_query = base64.urlsafe_b64encode(self.query.encode("utf-8")).decode("ascii")
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
            response_ip = requests.get(self.url, params=self.parameters)
            response_ip.raise_for_status()

        except requests.RequestException as e:
            raise AnalyzerRunException(e)

        return response_ip.json()
