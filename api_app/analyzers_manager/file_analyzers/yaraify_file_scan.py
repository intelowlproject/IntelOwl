# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import json
import logging
import time

import requests

from api_app.analyzers_manager.classes import FileAnalyzer
from api_app.analyzers_manager.exceptions import (
    AnalyzerConfigurationException,
    AnalyzerRunException,
)
from api_app.analyzers_manager.observable_analyzers.yaraify import YARAify

logger = logging.getLogger(__name__)


class YARAifyFileScan(FileAnalyzer, YARAify):
    _api_key_identifier: str
    clamav_scan: bool
    unpack: bool
    share_file: bool
    skip_noisy: bool
    skip_known: bool

    def update(self) -> bool:
        pass

    def config(self, runtime_configuration: dict):
        FileAnalyzer.config(self, runtime_configuration)
        self.query = "lookup_hash"
        YARAify.config(self, runtime_configuration)
        self.search_term = self.md5

        self.max_tries = 200
        self.poll_distance = 3

        self.send_file = self._job.tlp == self._job.TLP.CLEAR.value
        if self.send_file and not hasattr(self, "_api_key_identifier"):
            raise AnalyzerConfigurationException("Unable to send file without having api_key_identifier set")

    def run(self):
        name_to_send = self.filename if self.filename else self.md5
        file = self.read_file_bytes()
        logger.info(f"checking hash: {self.md5}")

        hash_scan = YARAify.run(self)
        query_status = hash_scan.get("query_status")
        logger.info(f"{query_status=} for hash {self.md5}")

        if query_status == "ok":
            logger.info(f"found YARAify hash scan and returning it. {self.md5}")
            return hash_scan

        result = hash_scan
        if self.send_file:
            data = {
                "identifier": self._api_key_identifier,
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
            response = requests.post(self.url, files=files_, headers=self.authentication_header)
            response.raise_for_status()
            scan_response = response.json()
            scan_query_status = scan_response.get("query_status")
            if scan_query_status == "queued":
                task_id = scan_response.get("data", {}).get("task_id", "")
                if not task_id:
                    raise AnalyzerRunException(
                        f"task_id value is unexpected: {task_id}.Analysis was requested for md5 {self.md5}"
                    )
                for _try in range(self.max_tries):
                    try:
                        logger.info(
                            f"yara file scan md5 {self.md5} polling for"
                            f" result try #{_try + 1}."
                            f"task_id: {task_id}"
                        )
                        data = {"query": "get_results", "task_id": task_id}
                        response = requests.post(self.url, json=data, headers=self.authentication_header)
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
