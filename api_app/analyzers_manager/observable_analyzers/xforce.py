# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from urllib.parse import quote_plus

import requests
from requests.auth import HTTPBasicAuth

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from tests.mock_utils import MockUpResponse, if_mock_connections, patch


class XForce(classes.ObservableAnalyzer):
    base_url: str = "https://exchange.xforce.ibmcloud.com/api"
    web_url: str = "https://exchange.xforce.ibmcloud.com"

    _api_key_name: str
    _api_password_name: str
    malware_only: bool
    timeout: int = 5

    def run(self):
        auth = HTTPBasicAuth(self._api_key_name, self._api_password_name)
        headers = {"Accept": "application/json"}

        endpoints = self._get_endpoints()
        result = {}
        for endpoint in endpoints:
            try:
                if self.observable_classification == self.ObservableTypes.URL:
                    observable_to_check = quote_plus(self.observable_name)
                else:
                    observable_to_check = self.observable_name
                url = f"{self.base_url}/{endpoint}/{observable_to_check}"
                response = requests.get(
                    url, auth=auth, headers=headers, timeout=self.timeout
                )
                if response.status_code == 404:
                    result["found"] = False
                else:
                    response.raise_for_status()
                result[endpoint] = response.json()
                path = self.observable_classification
                if self.observable_classification == self.ObservableTypes.DOMAIN:
                    path = self.ObservableTypes.URL
                elif self.observable_classification == self.ObservableTypes.HASH:
                    path = "malware"
                result[endpoint][
                    "link"
                ] = f"{self.web_url}/{path}/{observable_to_check}"
            except requests.RequestException as e:
                raise AnalyzerRunException(e)

        return result

    def _get_endpoints(self):
        """Return API endpoints for observable type

        :return: API endpoints
        :rtype: list
        """
        endpoints = []
        if self.observable_classification == self.ObservableTypes.IP:
            if not self.malware_only:
                endpoints.extend(["ipr", "ipr/history"])
            endpoints.append("ipr/malware")
        elif self.observable_classification == self.ObservableTypes.HASH:
            endpoints.append("malware")
        elif self.observable_classification in [
            self.ObservableTypes.URL,
            self.ObservableTypes.DOMAIN,
        ]:
            if not self.malware_only:
                endpoints.extend(["url", "url/history"])
            endpoints.append("url/malware")
        else:
            raise AnalyzerRunException(
                f"{self.observable_classification} not supported"
            )

        return endpoints

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
