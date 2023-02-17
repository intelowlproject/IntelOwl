# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import requests

from api_app.analyzers_manager.classes import FileAnalyzer
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from tests.mock_utils import MockResponse, if_mock_connections, patch


class MalpediaScan(FileAnalyzer):
    """
    Scan a binary against all YARA rules in Malpedia.
    """

    base_url = "https://malpedia.caad.fkie.fraunhofer.de/api"
    url = base_url + "/scan/binary"

    def set_params(self, params):
        self.__api_key = self._secrets["api_key_name"]

    def run(self):
        # get file
        binary = self.read_file_bytes()
        # construct req
        headers = {"Authorization": f"APIToken {self.__api_key}"}
        files = {"file": binary}

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
                    return_value=MockResponse({}, 200),
                )
            )
        ]
        return super()._monkeypatch(patches=patches)
