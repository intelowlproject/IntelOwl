# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import re

import requests

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from intel_owl.consts import REGEX_CVE, REGEX_EMAIL
from tests.mock_utils import MockResponse, if_mock_connections, patch


class Spyse(classes.ObservableAnalyzer):
    base_url: str = "https://api.spyse.com/v4/data/"

    def set_params(self, params):
        self.__api_key = self._secrets["api_key_name"]

    def __build_spyse_api_uri(self) -> str:
        if self.observable_classification == self.ObservableTypes.DOMAIN:
            endpoint = "domain"
        elif self.observable_classification == self.ObservableTypes.IP:
            endpoint = "ip"
        elif self.observable_classification == self.ObservableTypes.GENERIC:
            # it may be email
            if re.match(REGEX_EMAIL, self.observable_name):
                endpoint = "email"
            # it may be cve
            elif re.match(REGEX_CVE, self.observable_name):
                endpoint = "cve"
            else:
                raise AnalyzerRunException(
                    f"{self.analyzer_name} with `generic` supports email and CVE only."
                )
        else:
            raise AnalyzerRunException(
                f"{self.observable_classification} not supported."
                "Supported are: IP, domain and generic."
            )
        return f"{self.base_url}/{endpoint}/{self.observable_name}"

    def run(self):
        headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {self.__api_key}",
        }
        api_uri = self.__build_spyse_api_uri()
        try:
            response = requests.get(api_uri, headers=headers)
            response.raise_for_status()
        except requests.RequestException as e:
            raise AnalyzerRunException(e)

        result = response.json()
        return result

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
