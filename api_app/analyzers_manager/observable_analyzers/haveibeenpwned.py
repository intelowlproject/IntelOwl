import requests

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from tests.mock_utils import MockResponse, if_mock_connections, patch


class HaveIBeenPwned(classes.ObservableAnalyzer):
    base_url: str = "https://haveibeenpwned.com/api/v3/breachedaccount/"

    truncate_response: bool
    include_unverified: bool
    domain: str
    _api_key_name: str

    def run(self):
        params = {
            "truncateResponse": self.truncate_response,
            "includeUnverified": self.include_unverified,
        }
        if self.domain:
            params["domain"] = self.domain

        headers = {"hibp-api-key": self._api_key_name}

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
