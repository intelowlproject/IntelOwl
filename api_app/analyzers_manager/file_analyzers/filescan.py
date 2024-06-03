# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging
import time

import requests

from api_app.analyzers_manager.classes import FileAnalyzer
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from tests.mock_utils import MockUpResponse, if_mock_connections, patch

logger = logging.getLogger(__name__)


class FileScanUpload(FileAnalyzer):
    """FileScan_Upload_File analyzer"""

    max_tries: int = 30
    poll_distance: int = 10
    url = "https://www.filescan.io/api"
    _api_key: str

    def run(self):
        task_id = self.__upload_file_for_scan()
        report = self.__fetch_report(task_id)
        return report

    def __upload_file_for_scan(self) -> int:
        binary = self.read_file_bytes()
        if not binary:
            raise AnalyzerRunException("File is empty")
        response = requests.post(
            self.url + "/scan/file",
            files={"file": (self.filename, binary)},
            headers={"X-Api-Key": self._api_key},
        )
        response.raise_for_status()

        return response.json()["flow_id"]

    def __fetch_report(self, task_id: int) -> dict:
        report = {}
        url = f"{self.url}/scan/{task_id}/report"
        params = {
            "filter": [
                "general",
                "wi:all",
                "o:all",
                "finalVerdict",
                "dr:all",
                "f:all",
                "fd:all",
            ]
        }
        obj_repr = self.__repr__()

        for chance in range(self.max_tries):
            logger.info(f"[POLLING] {obj_repr} -> #{chance + 1}/{self.max_tries}")
            response = requests.get(
                url, params=params, headers={"X-Api-Key": self._api_key}
            )
            report = response.json()
            if report["allFinished"]:
                break
            time.sleep(self.poll_distance)

        return report

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch(
                    "requests.get",
                    return_value=MockUpResponse({"allFinished": True}, 200),
                ),
                patch(
                    "requests.post",
                    return_value=MockUpResponse({"flow_id": 1}, 200),
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)
