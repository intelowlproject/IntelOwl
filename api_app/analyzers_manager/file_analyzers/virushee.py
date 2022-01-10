# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging
import time

import requests
from typing import Optional
from api_app.analyzers_manager.classes import FileAnalyzer
from api_app.exceptions import AnalyzerRunException
from tests.mock_utils import MockResponse, if_mock_connections, patch

logger = logging.getLogger(__name__)

class Virushee(FileAnalyzer):
    """Analyze a file against Virushee API"""

    def set_params(self, params):
        self.session = requests.Session()
        self.max_tries = 30
        self.poll_distance = 10
        self.request_url = "https://api.virushee.com/"
        self.to_force_scan = params.get("force_scan", False)

    def run(self):
        binary = self.read_file_bytes()
        if not binary:
            raise AnalyzerRunException("File is empty")
        if not self.to_force_scan:
            hash_result = self.__check_report_for_hash()
            if hash_result:
                return hash_result
        task_id = self.__upload_file(binary)
        result = self.__poll_status(task_id)
        return result

    def __check_report_for_hash(self) -> Optional[dict]:
        api_url = f"{self.request_url}file/hash/{self.md5}"
        try:
            response = requests.get(api_url)
            response.raise_for_status()
        except requests.RequestException:
            return None

    def __upload_file(self, binary) -> str:
        name_to_send = self.filename if self.filename else self.md5
        files = {"file": (name_to_send, binary)}
        upload_url = self.request_url + "file/upload"
        try:
            response = self.session.post(upload_url, files=files)
            response.raise_for_status()
        except requests.RequestException as error:
            raise AnalyzerRunException(error)
        return response.json()["task"]

    def __poll_status(self, task_id: str) -> dict:
        request_url = f"{self.request_url}file/task/{task_id}"
        chance = 0
        while True:
            logger.info(f"Polling #try{chance+1}")
            time.sleep(self.poll_distance)
            try:
                response = self.session.get(request_url)
                response.raise_for_status()
            except requests.RequestException as exc:
                raise AnalyzerRunException(exc)
            if response.status_code == 202:
                continue
            return response.json()

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch(
                    "requests.Session.get",
                    return_value=MockResponse({"message": "hash_found"}, 200),
                ),
                patch(
                    "requests.Session.post",
                    return_value=MockResponse(
                        {"task": "80ca33ee-2df2-489a-9444-886db9abc5f0"}, 201
                    ),
                ),
                patch(
                    "requests.Session.get",
                    return_value=MockResponse({"message": "analysis_in_progress"}, 202),
                ),
                patch(
                    "requests.Session.get",
                    return_value=MockResponse({"message":"invalid_analysis_task"}, 404),
                )
            )
        ]
        return super()._monkeypatch(patches=patches)
