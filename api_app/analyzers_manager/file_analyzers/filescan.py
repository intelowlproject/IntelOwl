# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging
import time

import requests

from api_app.analyzers_manager.classes import FileAnalyzer
from api_app.exceptions import AnalyzerRunException
from tests.mock_utils import MockResponse, if_mock_connections, patch

logger = logging.getLogger(__name__)


class FileScanUpload(FileAnalyzer):
    """FileScan_Upload_File analyzer"""

    def set_params(self, params):
        self.max_tries = 30
        self.poll_distance = 10
        self.base_url = "https://www.filescan.io/api"

    def run(self):
        task_id = self.__upload_file_for_scan()
        report = self.__fetch_report(task_id)
        return report

    def __upload_file_for_scan(self) -> int:
        binary = self.read_file_bytes()
        if not binary:
            raise AnalyzerRunException("File is empty")
        try:
            response = requests.post(
                self.base_url + "/scan/file", files={"file": (self.filename, binary)}
            )
            response.raise_for_status()
        except requests.RequestException as e:
            raise AnalyzerRunException(e)

        return response.json()["flow_id"]

    def __fetch_report(self, task_id: int) -> dict:
        report = {}
        url = f"{self.base_url}/scan/{task_id}/report"
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
            response = requests.get(url, params=params)
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
                    return_value=MockResponse({"allFinished": True}, 200),
                ),
                patch(
                    "requests.post",
                    return_value=MockResponse({"flow_id": 1}, 200),
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)
