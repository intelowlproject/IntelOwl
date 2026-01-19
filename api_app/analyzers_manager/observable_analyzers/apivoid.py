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
    url = "https://endpoint.apivoid.com"
    _api_key: str = None

    def update(self):
        pass

    def run(self):
        if self.observable_classification == Classification.DOMAIN.value:
            path = "domainbl"
            parameter = "host"
        elif self.observable_classification == Classification.IP.value:
            path = "iprep"
            parameter = "ip"
        elif self.observable_classification == Classification.URL.value:
            path = "urlrep"
            parameter = "url"
        else:
            raise AnalyzerConfigurationException("not supported")
        complete_url = f"{self.url}/{path}/v1/pay-as-you-go/?key={self._api_key}&{parameter}={self.observable_name}"
        r = requests.get(complete_url)
        r.raise_for_status()
        return r.json()
