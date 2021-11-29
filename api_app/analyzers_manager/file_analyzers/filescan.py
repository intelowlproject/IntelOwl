# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging
import time

import requests

from api_app.analyzers_manager.classes import FileAnalyzer
from api_app.exceptions import AnalyzerRunException
from tests.mock_utils import MockResponse, if_mock_connections, patch

logger = logging.getLogger(__name__)


class FileScan(FileAnalyzer):
    """Filescan Class"""

    def set_params(self, params):
        self.upload_file = params.get("upload_file", True)
        self.session = requests.Session()
        self.max_tries = 30
        self.poll_distance = 10
        self.request_url = "https://www.filescan.io/"

    def run(self):
        binary = self.read_file_bytes()
        if not binary:
            raise AnalyzerRunException("File is empty")
        task_id = self.__filescan_request_scan(binary)
        result = self.__poll_status(task_id)
        return result

    def __filescan_request_scan(self, binary) -> int:
        logger.info(f"Requesting Scan for: ({self.filename}), {self.md5}")
        name_to_send = self.filename if self.upload_file else self.md5
        files = {"file": (name_to_send, binary)}
        logger.info(f"Uploading for file analysis  of ({self.filename}), {self.md5}")
        response = self.session.post(self.request_url + "api/scan/file", files=files)
        if response.status_code != 200:
            logger.info(f"Error: {response.status_code}")
            raise AnalyzerRunException("Error Uploading File for Scan")
        json_response = response.json()
        task_id = json_response["flow_id"]
        return task_id

    def __poll_status(self, task_id: int) -> dict:
        for chance in range(self.max_tries):
            time.sleep(self.poll_distance)
            url = self.request_url + "api/scan/" + str(task_id) + "/report"
            logger.info(f"Polling #try{chance+1}")
            response = self.session.get(url)
            json_response = response.json()
            status = json_response.get("allFinished")
            if str(status) == "True":
                break
        return json_response

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch(
                    "requests.Session.get",
                    return_value=MockResponse({"task": {"status": "reported"}}, 200),
                ),
                patch(
                    "requests.Session.post",
                    return_value=MockResponse({}, 200),
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)
