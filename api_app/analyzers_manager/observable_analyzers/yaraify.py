# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
import logging

import requests

from api_app.analyzers_manager.classes import ObservableAnalyzer
from api_app.choices import Classification
from api_app.mixins import AbuseCHMixin

logger = logging.getLogger(__name__)


class YARAify(AbuseCHMixin, ObservableAnalyzer):
    url: str = "https://yaraify-api.abuse.ch/api/v1/"

    query: str
    result_max: int
    _api_key_name: str

    def update(self) -> bool:
        pass

    def run(self):
        data = {"search_term": self.observable_name, "query": self.query}

        if self.observable_classification == Classification.GENERIC:
            data["result_max"] = self.result_max

        if getattr(self, "_api_key_name", None):
            data["malpedia-token"] = self._api_key_name

        response = requests.post(self.url, json=data, headers=self.authentication_header)
        response.raise_for_status()

        result = response.json()
        return result
