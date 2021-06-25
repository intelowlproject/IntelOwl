# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import requests
import logging

from api_app.exceptions import AnalyzerConfigurationException
from api_app.script_analyzers import classes
from intel_owl import secrets

logger = logging.getLogger(__name__)


class HoneyDB(classes.ObservableAnalyzer):
    base_url = "https://honeydb.io/api"

    def set_config(self, additional_config_params):
        api_key_name = additional_config_params.get("api_key_name", "HONEYDB_API_KEY")
        api_id_name = additional_config_params.get("api_id_name", "HONEYDB_API_ID")
        self.analysis_type = additional_config_params.get("honeydb_analysis", "all")
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
        self.__api_key = secrets.get_secret(api_key_name)
        self.__api_id = secrets.get_secret(api_id_name)
        if not self.__api_key:
            raise AnalyzerConfigurationException("No HoneyDB API Key retrieved")
        if not self.__api_id:
            raise AnalyzerConfigurationException("No HoneyDB API ID retrieved")
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
