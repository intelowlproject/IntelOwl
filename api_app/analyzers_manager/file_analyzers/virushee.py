# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging
import time
from typing import Optional

import requests

from api_app.analyzers_manager.classes import FileAnalyzer
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from tests.mock_utils import MockUpResponse, if_mock_connections, patch

logger = logging.getLogger(__name__)


class VirusheeFileUpload(FileAnalyzer):
    """Analyze a file against Virushee API"""

    max_tries = 30
    poll_distance = 10
    base_url = "https://api.virushee.com"

    force_scan: bool
    _api_key_name: str

    def config(self):
        super().config()
        self.__session = requests.Session()
        if not hasattr(self, "_api_key_name"):
            logger.info(f"{self.__repr__()} -> Continuing w/o API key..")
        else:
            self.__session.headers["X-API-Key"] = self._api_key_name

    def run(self):
        binary = self.read_file_bytes()
        if not binary:
            raise AnalyzerRunException("File is empty")
        if not self.force_scan:
            hash_result = self.__check_report_for_hash()
            if hash_result:
                return hash_result
        task_id = self.__upload_file(binary)
        result = self.__poll_status_and_result(task_id)
        return result

    def __check_report_for_hash(self) -> Optional[dict]:
        response_json = None
        try:
            response = self.__session.get(f"{self.base_url}/file/hash/{self.md5}")
            if response.status_code == 404:  # hash not found in db
                return response_json
            response.raise_for_status()
            response_json = response.json()
        except requests.RequestException as exc:
            raise AnalyzerRunException(str(exc))

        return response_json

    def __upload_file(self, binary: bytes) -> str:
        name_to_send = self.filename if self.filename else self.md5
        files = {"file": (name_to_send, binary)}
        try:
            response = self.__session.post(f"{self.base_url}/file/upload", files=files)
            response.raise_for_status()
        except requests.RequestException as exc:
            raise AnalyzerRunException(str(exc))
        return response.json()["task"]

    def __poll_status_and_result(self, task_id: str) -> dict:
        response_json = None
        url = f"{self.base_url}/file/task/{task_id}"
        for chance in range(self.max_tries):
            logger.info(f"Polling try#{chance+1}")
            try:
                response = self.__session.get(url)
                response.raise_for_status()
            except requests.RequestException as exc:
                raise AnalyzerRunException(str(exc))
            response_json = response.json()
            if response.status_code == 200:
                break
            time.sleep(self.poll_distance)

        return response_json

    @classmethod
    def _monkeypatch(cls):
        cls.poll_distance = 0  # for tests
        patches = [
            if_mock_connections(
                patch(
                    "requests.Session.get",
                    side_effect=[
                        MockUpResponse({"message": "hash_not_found"}, 404),
                        MockUpResponse({"message": "analysis_in_progress"}, 202),
                        MockUpResponse({"result": "test"}, 200),
                    ],
                ),
                patch(
                    "requests.Session.post",
                    return_value=MockUpResponse({"task": "123-456-789"}, 201),
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)
