# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import base64

import requests

from api_app.analyzers_manager.classes import ObservableAnalyzer
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from tests.mock_utils import MockUpResponse, if_mock_connections, patch


class FileScanSearch(ObservableAnalyzer):
    """FileScan_Search analyzer"""

    url: str = "https://www.filescan.io/api/reports/search"
    _api_key: str

    @classmethod
    def update(cls) -> bool:
        pass

    def run(self):
        """Runs the FileScan_Search analyzer"""
        observable_name_base64 = base64.b64encode(
            self.observable_name.encode()
        ).decode()
        endpoint = "?query={input}"
        url = f"{self.url}/{endpoint.format(input=observable_name_base64)}"
        try:
            response = requests.get(url, headers={"X-Api-Key": self._api_key})
            response.raise_for_status()
        except requests.RequestException as error:
            raise AnalyzerRunException(error)
        return {**response.json(), "query": observable_name_base64}

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch(
                    "requests.get",
                    return_value=MockUpResponse(
                        {
                            "items": [],
                            "count": 0,
                            "count_search_params": 1,
                            "method": "and",
                        },
                        200,
                    ),
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)
