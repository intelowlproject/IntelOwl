import requests

from api_app.analyzers_manager import classes
from tests.mock_utils import MockResponse, if_mock_connections, patch


class BitcoinAbuseAPI(classes.ObservableAnalyzer):
    url: str = "https://www.bitcoinabuse.com/api/reports/check"

    def set_params(self, params):
        self.__api_key = self._secrets["api_key_name"]

    def run(self):
        params = {"address": self.observable_name, "api_token": self.__api_key}

        response = requests.get(self.url, params=params)
        response.raise_for_status()

        return response.json()

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
