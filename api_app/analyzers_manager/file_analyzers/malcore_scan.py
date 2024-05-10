# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging
import time

import requests

from api_app.analyzers_manager.classes import FileAnalyzer
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from tests.mock_utils import MockUpResponse, if_mock_connections, patch

logger = logging.getLogger(__name__)


class MalcoreScan(FileAnalyzer):
    base_url = "https://api.malcore.io/api/"
    _api_key_name: str
    max_tries: int
    poll_distance: int

    def update(self) -> bool:
        pass

    def run(self):
        self.headers = {"apiKey": self._api_key_name}

        binary = self.read_file_bytes()
        files = {"filename1": binary}
        logger.info(f"Sending {self.md5} to Malcore")
        response = requests.post(
            self.base_url + "upload", headers=self.headers, files=files
        )
        response.raise_for_status()

        json_response = response.json()
        uuid = json_response.get("data", {}).get("data", {}).get("uuid", "")
        if not uuid:
            raise AnalyzerRunException(f"Failed analysis for {self.md5}")

        for _try in range(self.max_tries):
            logger.info(f"polling malcore try #{_try + 1}")
            self.result = self._get_status(uuid)["data"]
            if "status" not in self.result and "msg" not in self.result:
                logger.info(f"Malcore analysis successfully retrieved for {self.md5}")
                break

            time.sleep(self.poll_distance)

        return self.result

    def _get_status(self, uuid):
        payload = {"uuid": uuid}
        response = requests.post(
            self.base_url + "status", headers=self.headers, json=payload
        )
        response.raise_for_status()
        return response.json()

    @classmethod
    def _monkeypatch(cls):
        response = {
            "data": {
                "data": {"uuid": "uuidrandom"},
                "status": "status",
                "msg": "message",
            }
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
