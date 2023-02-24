import requests

from api_app.analyzers_manager.classes import ObservableAnalyzer
from tests.mock_utils import MockResponse, if_mock_connections, patch


class Crowdsec(ObservableAnalyzer):
    def set_params(self, params):
        self.__api_key = self._secrets["api_key_name"]

    def run(self):
        headers = {"x-api-key": self.__api_key}
        url = f"https://cti.api.crowdsec.net/v2/smoke/{self.observable_name}"
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        result = response.json()
        result["link"] = f"https://app.crowdsec.net/cti/{self.observable_name}"
        return result

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch(
                    "requests.get",
                    return_value=MockResponse(
                        {
                            "behaviors": [
                                {
                                    "name": "http:exploit",
                                    "label": "HTTP Exploit",
                                    "description": "bla bla",
                                }
                            ]
                        },
                        200,
                    ),
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)
