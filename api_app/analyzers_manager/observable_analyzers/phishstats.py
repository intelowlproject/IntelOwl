import requests

from api_app.analyzers_manager.classes import ObservableAnalyzer
from api_app.exceptions import AnalyzerRunException
from tests.mock_utils import MockResponse, if_mock_connections, patch


class PhishStats(ObservableAnalyzer):
    """
    Analyzer that uses PhishStats API to check if the observable is a phishing site.
    """

    base_url: str = "https://phishstats.info:2096/api/phishing?_where=(ip,eq,{input})"

    def __build_phishstats_url(self) -> str:
        if self.observable_classification == self.ObservableTypes.IP:
            return self.base_url.format(input=self.observable_name)
        else:
            raise AnalyzerRunException("PhishStats only works with IP addresses")

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
