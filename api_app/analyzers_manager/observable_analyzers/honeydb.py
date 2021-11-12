# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging

import requests

from api_app.analyzers_manager import classes
from api_app.exceptions import AnalyzerConfigurationException
from tests.mock_utils import MockResponse, if_mock_connections, patch

logger = logging.getLogger(__name__)


class HoneyDB(classes.ObservableAnalyzer):
    base_url = "https://honeydb.io/api"

    def set_params(self, params):
        self.analysis_type = params.get("honeydb_analysis", "all")
        self.endpoints = [
            "scan_twitter",
            "ip_query",
            "ip_history",
            "internet_scanner",
            "ip_info",
        ]
        if self.analysis_type not in self.endpoints and self.analysis_type != "all":
            raise AnalyzerConfigurationException(
                f"analysis_type is not valid: {self.analysis_type}"
            )

        # set secrets
        self.__api_key = self._secrets["api_key_name"]
        self.__api_id = self._secrets["api_id_name"]
        self.headers = {
            "X-HoneyDb-ApiKey": self.__api_key,
            "X-HoneyDb-ApiId": self.__api_id,
        }
        self.result = {}

    def run(self):
        if self.analysis_type == "all":
            for endpoint in self.endpoints:
                self._request_analysis(endpoint)
        else:
            self._request_analysis(self.analysis_type)

        return self.result

    def _request_analysis(self, endpoint):
        if endpoint == "scan_twitter":
            url = f"{self.base_url}/twitter-threat-feed/{self.observable_name}"
        elif endpoint == "ip_query":
            url = f"{self.base_url}/netinfo/lookup/{self.observable_name}"
        elif endpoint == "ip_history":
            url = f"{self.base_url}/ip-history/{self.observable_name}"
        elif endpoint == "internet_scanner":
            url = f"{self.base_url}/internet-scanner/info/{self.observable_name}"
        elif endpoint == "ip_info":
            url = f"{self.base_url}/ipinfo/{self.observable_name}"
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
