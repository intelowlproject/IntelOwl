# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import requests

from api_app.analyzers_manager import classes
from tests.mock_utils import MockUpResponse, if_mock_connections, patch


class Hunter_Io(classes.ObservableAnalyzer):
    url: str = "https://api.hunter.io/v2/domain-search?"

    _api_key_name: str

    @classmethod
    def update(cls) -> bool:
        pass

    def run(self):
        url = f"{self.url}domain={self.observable_name}&api_key={self._api_key_name}"
        response = requests.get(url)
        response.raise_for_status()

        return response.json()

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
