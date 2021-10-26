# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import requests

from api_app.exceptions import AnalyzerRunException
from api_app.analyzers_manager.classes import ObservableAnalyzer

from tests.mock_utils import if_mock_connections, patch, MockResponse


class CryptoScamDB(ObservableAnalyzer):
    base_url: str = "https://api.cryptoscamdb.org/v1/check/{input}"

    def run(self):
        url = self.base_url.format(input=self.observable_name)
        try:
            response = requests.get(url)
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
                    return_value=MockResponse({"success": True}, 200),
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)
