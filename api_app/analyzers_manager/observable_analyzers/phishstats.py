# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import requests

from api_app.analyzers_manager.classes import ObservableAnalyzer
from api_app.exceptions import AnalyzerRunException
from tests.mock_utils import MockResponse, if_mock_connections, patch


class PhishStats(ObservableAnalyzer):
    """
    Analyzer that uses PhishStats API to check if the observable is a phishing site.
    """

    base_url: str = "https://phishstats.info:2096/api/"

    def __build_phishstats_url(self) -> str:
        if self.observable_classification == self.ObservableTypes.IP:
            endpoint = "phishing?_where=(ip,eq,{input})&_sort=-date"
        elif self.observable_classification == self.ObservableTypes.URL:
            endpoint = "phishing?_where=(url,like,~{input}~)&_sort=-date"
        elif self.observable_classification == self.ObservableTypes.DOMAIN:
            endpoint = "phishing?_where=(url,like,~{input}~)&_sort=-date"
        elif self.observable_classification == self.ObservableTypes.GENERIC:
            endpoint = "phishing?_where=(title,like,~{input}~)&_sort=-date"
        else:
            raise AnalyzerRunException(
                "Phishstats require either of IP, URL, Domain or Generic"
            )
        return f"{self.base_url}/{endpoint.format(input=self.observable_name)}"

    def run(self):
        api_uri = self.__build_phishstats_url()
        try:
            response = requests.get(api_uri)
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
