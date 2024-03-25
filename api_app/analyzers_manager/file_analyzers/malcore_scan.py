# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import requests

from api_app.analyzers_manager.classes import FileAnalyzer
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from tests.mock_utils import MockUpResponse, if_mock_connections, patch


class MalcoreScan(FileAnalyzer):
    url = "https://api.malcore.io/api/upload"

    _api_key_name: str

    def run(self):
        binary = self.read_file_bytes()
        headers = {"apiKey": self._api_key_name}
        files = {"filename1": binary}

        try:
            response = requests.post(self.url, headers=headers, files=files)
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
                    "requests.post",
                    return_value=MockUpResponse({}, 200),
                )
            )
        ]
        return super()._monkeypatch(patches=patches)
