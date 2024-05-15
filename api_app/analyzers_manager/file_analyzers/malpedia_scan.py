# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import requests

from api_app.analyzers_manager.classes import FileAnalyzer
from tests.mock_utils import MockUpResponse, if_mock_connections, patch


class MalpediaScan(FileAnalyzer):
    """
    Scan a binary against all YARA rules in Malpedia.
    """

    url = "https://malpedia.caad.fkie.fraunhofer.de/api"
    binary_url = url + "/scan/binary"

    _api_key_name: str

    def run(self):
        # get file
        binary = self.read_file_bytes()
        # construct req
        headers = {"Authorization": f"APIToken {self._api_key_name}"}
        files = {"file": binary}
        response = requests.post(self.binary_url, headers=headers, files=files)
        response.raise_for_status()

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
