# flake8: noqa
# done for the mocked response,
# everything else is linted and tested
# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
import requests

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import AnalyzerConfigurationException
from api_app.choices import Classification


class ApiVoidAnalyzer(classes.ObservableAnalyzer):
    url = "https://api.apivoid.com/v2"
    _api_key: str = None

    def update(self):
        pass

    def run(self):
        if self.observable_classification == Classification.DOMAIN.value:
            path = "domain-reputation"
            parameter = "host"
        elif self.observable_classification == Classification.IP.value:
            path = "ip-reputation"
            parameter = "ip"
        elif self.observable_classification == Classification.URL.value:
            path = "url-reputation"
            parameter = "url"
        else:
            raise AnalyzerConfigurationException("not supported")

        complete_url = f"{self.url}/{path}"

        headers = {
            "Content-Type": "application/json",
            "X-API-Key": self._api_key,
        }

        payload = {parameter: self.observable_name}

        r = requests.post(complete_url, headers=headers, json=payload)
        r.raise_for_status()
        return r.json()
