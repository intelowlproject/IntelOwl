# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import requests

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from tests.mock_utils import MockUpResponse, if_mock_connections, patch


class Ip2whois(classes.ObservableAnalyzer):
    base_url: str = "https://api.ip2whois.com/v2"
    _api_key_name: str

    def get_response(self, payload):
        return requests.get(self.base_url, params=payload)

    def run(self):
        try:
            params = {
                "key": self._api_key_name,
                "domain": self.observable_name,
            }

            location_info = self.get_response(params)
            location_info.raise_for_status()

        except requests.RequestException as e:
            raise AnalyzerRunException(e)

        response = location_info.json()
        return response

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch(
                    "requests.get",
                    return_value=MockUpResponse({}, 200),
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)
