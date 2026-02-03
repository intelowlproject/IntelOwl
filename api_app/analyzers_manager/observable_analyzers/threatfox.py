# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import json
import logging

import requests

from api_app.analyzers_manager import classes
from api_app.mixins import AbuseCHMixin

logger = logging.getLogger(__name__)


class ThreatFox(AbuseCHMixin, classes.ObservableAnalyzer):
    url: str = "https://threatfox-api.abuse.ch/api/v1/"
    disable: bool = False  # optional

    def update(self) -> bool:
        pass

    def run(self):
        if self.disable:
            return {"disabled": True}

        payload = {"query": "search_ioc", "search_term": self.observable_name}

        response = requests.post(
            self.url,
            data=json.dumps(payload),
            headers=self.authentication_header,
        )
        response.raise_for_status()

        result = response.json()
        data = result.get("data", [])
        if data and isinstance(data, list):
            for index, element in enumerate(data):
                ioc_id = element.get("id", "")
                if ioc_id:
                    result["data"][index]["link"] = f"https://threatfox.abuse.ch/ioc/{ioc_id}"
        return result
