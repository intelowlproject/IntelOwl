# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import requests
from requests.auth import HTTPBasicAuth
from urllib.parse import quote_plus

from api_app.exceptions import AnalyzerRunException
from api_app.analyzers_manager import classes


class XForce(classes.ObservableAnalyzer):
    base_url: str = "https://api.xforce.ibmcloud.com"

    def set_params(self, params):
        self.__api_key = self._secrets["api_key_name"]
        self.__api_password = self._secrets["api_password_name"]

    def run(self):
        auth = HTTPBasicAuth(self.__api_key, self.__api_password)

        endpoints = self._get_endpoints()
        result = {}
        for endpoint in endpoints:
            try:
                if self.observable_classification == self.ObservableTypes.URL:
                    observable_to_check = quote_plus(self.observable_name)
                else:
                    observable_to_check = self.observable_name
                url = f"{self.base_url}/{endpoint}/{observable_to_check}"
                response = requests.get(url, auth=auth)
                response.raise_for_status()
            except requests.RequestException as e:
                raise AnalyzerRunException(e)

            result[endpoint] = response.json()
        return result

    def _get_endpoints(self):
        """Return API endpoints for observable type

        :return: API endpoints
        :rtype: list
        """

        if self.observable_classification == self.ObservableTypes.IP:
            endpoints = ["ipr", "ipr/history", "ipr/malware"]
        elif self.observable_classification == self.ObservableTypes.HASH:
            endpoints = ["malware"]
        elif self.observable_classification == self.ObservableTypes.URL:
            endpoints = ["url", "url/history", "url/malware"]
        else:
            raise AnalyzerRunException(
                f"{self.observable_classification} not supported"
            )

        return endpoints
