# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import base64
import logging

import requests

from api_app.analyzers_manager.classes import ObservableAnalyzer
from api_app.exceptions import AnalyzerRunException
from tests.mock_utils import MockResponse, if_mock_connections, patch

logger = logging.getLogger(__name__)


class FileScanSearch(ObservableAnalyzer):
    """FileScan_Search analyzer"""

    base_url: str = "https://www.filescan.io/api"

    def __build_filescan_url(self) -> str:
        """Builds the URL for the Filescan Search API"""
        observableName = self.observable_name
        observableName_bytes = observableName.encode("ascii")
        base64_bytes = base64.b64encode(observableName_bytes)
        EncodedObservableName = base64_bytes.decode("ascii")
        endpoint = "reports/search?query={input}"
        return f"{self.base_url}/{endpoint.format(input=EncodedObservableName)}"

    def run(self):
        """Runs the FileScan_Search analyzer"""
        url = self.__build_filescan_url()
        response = requests.get(url)
        if response.status_code != 200:
            raise AnalyzerRunException(f"FileScan_Search: {response.status_code}")
        self.result = response.json()
        return self.result

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
