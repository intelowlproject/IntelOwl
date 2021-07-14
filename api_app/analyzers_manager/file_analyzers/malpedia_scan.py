# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import requests

from api_app.exceptions import AnalyzerRunException
from api_app.analyzers_manager.classes import FileAnalyzer
from api_app.helpers import get_binary

from tests.mock_utils import patch, if_mock, mocked_requests


@if_mock(
    [
        patch(
            "requests.post",
            side_effect=mocked_requests,
        )
    ]
)
class MalpediaScan(FileAnalyzer):
    base_url: str = "https://malpedia.caad.fkie.fraunhofer.de/api/"

    def set_params(self, params):
        self.__api_key = self._secrets["api_key_name"]

    def run(self):
        return self._scan_binary()

    def _scan_binary(self):
        """scan a binary against all YARA rules in Malpedia"""

        url = self.base_url + "scan/binary"
        headers = {"Authorization": f"APIToken {self.__api_key}"}
        binary = get_binary(self.job_id)
        files = {"file": binary}

        try:
            response = requests.post(url, headers=headers, files=files)
            response.raise_for_status()
        except requests.RequestException as e:
            raise AnalyzerRunException(e)

        result = response.json()
        return result
