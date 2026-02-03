# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import re

import requests

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from api_app.choices import Classification
from intel_owl.consts import REGEX_CVE, REGEX_EMAIL


class Spyse(classes.ObservableAnalyzer):
    url: str = "https://api.spyse.com/v4/data/"

    _api_key_name: str

    @classmethod
    def update(cls) -> bool:
        pass

    def __build_spyse_api_uri(self) -> str:
        if self.observable_classification == Classification.DOMAIN:
            endpoint = "domain"
        elif self.observable_classification == Classification.IP:
            endpoint = "ip"
        elif self.observable_classification == Classification.GENERIC:
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
                f"{self.observable_classification} not supported. Supported are: IP, domain and generic."
            )
        return f"{self.url}/{endpoint}/{self.observable_name}"

    def run(self):
        headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {self._api_key_name}",
        }
        api_uri = self.__build_spyse_api_uri()
        response = requests.get(api_uri, headers=headers)
        response.raise_for_status()

        result = response.json()
        return result
