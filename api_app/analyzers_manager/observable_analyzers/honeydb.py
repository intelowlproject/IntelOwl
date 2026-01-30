# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging
from typing import Dict

import requests

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import AnalyzerConfigurationException

logger = logging.getLogger(__name__)


class HoneyDB(classes.ObservableAnalyzer):
    url = "https://honeydb.io/api"
    # set secrets
    _api_key_name: str
    _api_id_name: str
    honeydb_analysis: str

    @classmethod
    def update(cls) -> bool:
        pass

    def config(self, runtime_configuration: Dict):
        super().config(runtime_configuration)
        self.headers = {
            "X-HoneyDb-ApiKey": self._api_key_name,
            "X-HoneyDb-ApiId": self._api_id_name,
        }
        self.result = {}
        self.endpoints = [
            "scan_twitter",
            "ip_query",
            "ip_history",
            "internet_scanner",
            "ip_info",
        ]
        if self.honeydb_analysis not in self.endpoints and self.honeydb_analysis != "all":
            raise AnalyzerConfigurationException(f"analysis_type is not valid: {self.honeydb_analysis}")

    def run(self):
        if self.honeydb_analysis == "all":
            for endpoint in self.endpoints:
                self._request_analysis(endpoint)
        else:
            self._request_analysis(self.honeydb_analysis)

        return self.result

    def _request_analysis(self, endpoint):
        if endpoint == "scan_twitter":
            url = f"{self.url}/twitter-threat-feed/{self.observable_name}"
        elif endpoint == "ip_query":
            url = f"{self.url}/netinfo/lookup/{self.observable_name}"
        elif endpoint == "ip_history":
            url = f"{self.url}/ip-history/{self.observable_name}"
        elif endpoint == "internet_scanner":
            url = f"{self.url}/internet-scanner/info/{self.observable_name}"
        elif endpoint == "ip_info":
            url = f"{self.url}/ipinfo/{self.observable_name}"
        else:
            logger.error(f"endpoint {endpoint} not supported")
            return
        try:
            response = requests.get(url, headers=self.headers)
            response.raise_for_status()
        except Exception as e:
            logger.exception(e)
            self.result[endpoint] = {"error": e}
        else:
            self.result[endpoint] = response.json()
