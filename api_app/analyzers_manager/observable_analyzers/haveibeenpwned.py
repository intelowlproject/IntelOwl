import requests

from api_app.analyzers_manager import classes
from api_app.exceptions import AnalyzerRunException
from tests.mock_utils import MockResponse, if_mock_connections, patch


class HaveIBeenPwned(classes.ObservableAnalyzer):
    base_url: str = "https://haveibeenpwned.com/api/v3/breachedaccount/"

    def set_params(self, params):
        self.truncate_response = params.get("truncate_response", True)
        self.include_unverified = params.get("include_unverified", True)
        self.domain = params.get("domain", None)
        self.__api_key = self._secrets["api_key_name"]

    def run(self):
        params = {
            "truncateResponse": self.truncate_response,
            "includeUnverified": self.include_unverified,
        }
        if self.domain:
            params["domain"] = self.domain

        headers = {"hibp-api-key": self.__api_key}

        try:
            response = requests.get(
                self.base_url + self.observable_name, params=params, headers=headers
            )
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
