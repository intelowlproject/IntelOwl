# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import json
import logging
import time

import requests

from api_app.analyzers_manager.classes import FileAnalyzer
from api_app.analyzers_manager.observable_analyzers.yaraify import YARAify
from api_app.exceptions import AnalyzerRunException
from tests.mock_utils import MockResponse, if_mock_connections, patch

logger = logging.getLogger(__name__)


class YARAifyFileScan(FileAnalyzer, YARAify):
    def set_params(self, params):
        YARAify.set_params(self, params)
        self.search_term = self.md5
        self.__api_key_identifier = self._secrets["api_key_identifier"]

        self.send_file: bool = params.get("send_file", True)
        self.clamav_scan: bool = params.get("clamav_scan", True)
        self.unpack: bool = params.get("unpack", False)
        self.share_file: bool = params.get("share_file", False)
        self.skip_noisy: bool = params.get("skip_noisy", True)
        self.skip_known: bool = params.get("skip_known", False)

        self.max_tries = 200
        self.poll_distance = 3

    def run(self):
        name_to_send = self.filename if self.filename else self.md5
        file = self.read_file_bytes()

        hash_scan = YARAify.run(self)
        query_status = hash_scan.get("query_status")

        if query_status == "ok":
            logger.info(f"found YARAify hash scan and returning it. {self.md5}")
            hash_scan["hash_check_found"] = True
            return hash_scan

        result = hash_scan
        if self.send_file:
            data = {
                "identifier": self.__api_key_identifier,
                # the server wants either 0 or 1
                # https://yaraify.abuse.ch/api/#file-scan
                "clamav_scan": int(self.clamav_scan),
                "unpack": int(self.unpack),
                "share_file": int(self.share_file),
                "skip_noisy": int(self.skip_noisy),
                "skip_known": int(self.skip_known),
            }

            files_ = {
                "json_data": (None, json.dumps(data), "application/json"),
                "file": (name_to_send, file),
            }
            logger.info(f"yara file scan md5 {self.md5} sending sample for analysis")
            response = requests.post(self.url, files=files_)
            response.raise_for_status()
            scan_response = response.json()
            scan_query_status = scan_response.get("query_status")
            if scan_query_status == "queued":
                task_id = scan_response.get("data", {}).get("task_id", "")
                if not task_id:
                    raise AnalyzerRunException(
                        f"task_id value is unexpected: {task_id}."
                        f"Analysis was requested for md5 {self.md5}"
                    )
                for _try in range(self.max_tries):
                    try:
                        logger.info(
                            f"yara file scan md5 {self.md5} polling for"
                            f" result try #{_try + 1}."
                            f"task_id: {task_id}"
                        )
                        data = {"query": "get_results", "task_id": task_id}
                        response = requests.post(self.url, json=data)
                        response.raise_for_status()
                        task_response = response.json()
                        logger.debug(task_response)
                        data_results = task_response.get("data")
                        if isinstance(data_results, dict) and data_results:
                            logger.info(f"found scan result for {self.md5}")
                            break
                    except requests.RequestException as e:
                        logger.warning(e, stack_info=True)
                    time.sleep(self.poll_distance)
            else:
                raise AnalyzerRunException(
                    f"query_status value is unexpected: {scan_query_status}."
                    f"Analysis was requested for md5 {self.md5}"
                )

            result = response.json()

        return result

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch(
                    "requests.post",
                    side_effect=[
                        MockResponse({"query_status": "not-available"}, 200),
                        MockResponse(
                            {"query_status": "queued", "data": {"task_id": 123}}, 200
                        ),
                        MockResponse(
                            {"query_status": "ok", "data": {"static_results": []}}, 200
                        ),
                    ],
                )
            )
        ]
        return FileAnalyzer._monkeypatch(patches=patches)
