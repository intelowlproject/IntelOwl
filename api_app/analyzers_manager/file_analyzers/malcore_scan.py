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
        response = {
            "data": {
                "uuid": (
                    "256cca7c24d6f9e4-a781ac10-5294b2e1-"
                    "816c8b2d-fa97f27c-62aea6e24775b570"
                ),
                "status": "pending",
                "scan_id": "6606e6a6d73e1e6bb84bd7c9",
                "scan_url": (
                    "https://app.malcore.io/report"
                    "/6606e6a6d73e1e6bb84bd7ab/scan/undefined"
                ),
                "report_id": "6606e6a6d73e1e6bb84bd7ab",
            },
            "success": True,
            "messages": [
                {"code": 200, "type": "success", "message": "Scan is running"}
            ],
            "isMaintenance": False,
        }
        patches = [
            if_mock_connections(
                patch(
                    "requests.post",
                    return_value=MockUpResponse(response, 200),
                )
            )
        ]
        return super()._monkeypatch(patches=patches)
