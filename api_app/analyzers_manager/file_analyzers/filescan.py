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
    def set_params(self, params):
        self.upload_file = params.get("upload_file", True)
        self.session = requests.Session()
        self.request_url = "https://www.filescan.io/"
        self.task_id = 0
        self.result = {}
        self.max_post_tries = params.get("max_post_tries", 5)
        self.max_get_tries = params.get("max_poll_tries", 20)

    def run(self):
        binary = self.read_file_bytes()
        if not binary:
            raise AnalyzerRunException("File is empty")
        self.__filescan_request_scan(binary)
        # self.____filescan_poll_result()
        result = self.__filescan_poll_result()
        return result

    def __filescan_request_scan(self, binary):
        logger.info(f"Requesting Scan for: ({self.filename}), {self.md5}")

        name_to_send = self.filename if self.upload_file else self.md5
        files = {"file": (name_to_send, binary)}
        post_sucess = False
        for chance in range(self.max_post_tries):
            logger.info(
                f"#{chance} for file analysis  of ({self.filename}), {self.md5}"
            )
            response = self.session.post(
                self.request_url + "api/scan/file", files=files
            )
            upl = response.status_code
            logger.info(f"UPLOAD CODE: {upl}")
            if response.status_code != 200:
                logger.info(f"Error: {response.status_code}")
                time.sleep(5)
                continue
            else:
                post_sucess = True
                break
        if post_sucess:
            json_response = response.json()
            self.task_id = json_response["flow_id"]
            logger.info(f"TASK ID: {self.task_id}")
        else:
            raise AnalyzerRunException(
                "failed max tries to post file to Filescan for analysis"
            )

    def __filescan_poll_result(self):
        logger.info(
            f"polling result for ({self.filename},{self.md5}), task_id: {self.task_id}"
        )
        # get_sucess = False
        for chance in range(4):
            logger.info(
                f"polling request #{chance+1} for file ({self.filename}, {self.md5})"
            )
            url = self.request_url + "api/scan/" + str(self.task_id) + "/report"
            response = self.session.get(url)
            logger.info(f"REQUEST URL IS: {url}")
            json_response = response.json()
            logger.info(f"RESPONSE OBTAINED: {json_response}")
            resu = response.status_code
            logger.info(f"RESPONSE CODE: {resu}")
            status = json_response.get("allFinished")
            logger.info(f"Result for Request: {status}")
            # logger.info(json_response)
            # get_sucess = True
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
