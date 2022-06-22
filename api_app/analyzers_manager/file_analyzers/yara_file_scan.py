# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import json
import logging
import time
from typing import Dict

import requests

from api_app.analyzers_manager.classes import FileAnalyzer
from api_app.analyzers_manager.observable_analyzers.yara_search import YaraSearch
from tests.mock_utils import MockResponse, if_mock_connections, patch

logger = logging.getLogger(__name__)


class YaraFileScan(FileAnalyzer, YaraSearch):
    def set_params(self, params):
        self.url: str = "https://yaraify-api.abuse.ch/api/v1/"
        self.__api_key_identifier = self._secrets["api_key_identifier"]

        self.clamav_scan = params.get("clamav_scan", 1)
        self.unpack = params.get("unpack", 0)
        self.share_file = params.get("share_file", 0)

        self.max_tries = 200
        self.poll_distance = 3

    def run(self):
        name_to_send = self.filename if self.filename else self.md5
        file = self.read_file_bytes()

        hash_scan = self.before_file_scan(self.md5)
        query_status = hash_scan.get("query_status")

        if query_status == "ok":
            return hash_scan

        data = {
            "clamav_scan": self.clamav_scan,
            "unpack": self.unpack,
            "share_file": self.share_file,
            "identifier": self.__api_key_identifier,
        }

        files_ = {
            "json_data": (None, json.dumps(data), "application/json"),
            "file": (name_to_send, file),
        }

        logger.info(f"yara file scan md5 {self.md5} sending sample for analysis")
        for _try in range(self.max_tries):
            logger.info(
                f"yara file scan md5 {self.md5} polling for result try #{_try + 1}"
            )
            response = requests.post(self.url, files=files_)
            if response.status_code == 200:
                break
            time.sleep(self.poll_distance)

        result = response.json()
        return result

    def before_file_scan(self, hash) -> Dict:
        self.search_term = hash
        self.query = "lookup_hash"

        return self.scan()

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch(
                    "requests.post",
                    return_value=MockResponse({}, 200),
                )
            )
        ]
        return FileAnalyzer._monkeypatch(patches=patches)
