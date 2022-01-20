# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import requests

from api_app.analyzers_manager.classes import ObservableAnalyzer
from api_app.exceptions import AnalyzerRunException
from tests.mock_utils import MockResponse, if_mock_connections, patch


class VirusheeCheckHash(ObservableAnalyzer):
    base_url: str = "https://api.virushee.com/file/hash/{input}"

    def set_params(self, params):
        self.__session = requests.Session()
        api_key = self._secrets["api_key_name"]
        if api_key:
            self.__session.headers["X-API-Key"] = api_key

    def run(self):
        url = self.base_url.format(input=self.observable_name)

        try:
            response = self.__session.get(url)
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
                    "requests.Session.get",
                    return_value=MockResponse({"success": True}, 200),
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)
