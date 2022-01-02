# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging
import time

import requests

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.observable_analyzers import vt2_get
from api_app.exceptions import AnalyzerRunException
from tests.mock_utils import MockResponse, if_mock_connections, patch

logger = logging.getLogger(__name__)


class VirusTotalv2ScanFile(classes.FileAnalyzer):
    base_url: str = "https://www.virustotal.com/vtapi/v2/"

    def set_params(self, params):
        self.__api_key = self._secrets["api_key_name"]
        # this is a config value that can be used...
        # .. to force the waiting of the scan result anyway
        self.wait_for_scan_anyway = params.get("wait_for_scan_anyway", False)
        # max no. of tries when polling for result
        self.max_tries = params.get("max_tries", 10)
        # max 5 minutes waiting
        self.poll_distance = 30

    def run(self):
        result = None
        notify_url = self._secrets["url_key_name"]
        resp = self.__vt_request_scan(notify_url)

        # in case we didn't use the webhook to get the result of the scan,...
        # .. start a poll for the result
        # or in case we'd like to force the scan anyway from the configuration
        if not notify_url or self.wait_for_scan_anyway:
            scan_id = resp.get("scan_id", None)
            if not scan_id:
                raise (
                    AnalyzerRunException(
                        "no scan_id given by VirusTotal to retrieve the results."
                    )
                )
            result = self.__vt_poll_for_result(scan_id)

        return result if result else resp

    def __vt_request_scan(self, notify_url):
        binary = self.read_file_bytes()
        params = {"apikey": self.__api_key}
        if notify_url:
            params["notify_url"] = notify_url
        files = {"file": binary}

        try:
            resp = requests.post(
                self.base_url + "file/scan", files=files, params=params
            )
            resp.raise_for_status()
        except requests.RequestException as e:
            raise AnalyzerRunException(e)
        json_resp = resp.json()
        response_code = json_resp.get("response_code", 1)
        if response_code == -1:
            raise AnalyzerRunException("response code -1")
        return json_resp

    def __vt_poll_for_result(self, scan_id):
        for chance in range(self.max_tries):
            time.sleep(self.poll_distance)
            logger.info(f"vt2 polling: #{chance + 1}. job_id: #{self.job_id}")
            result = vt2_get.vt_get_report(self.__api_key, scan_id, "hash")
            response_code = result.get("response_code", 1)
            # response code -2 means the we still have to wait
            if response_code == -2:
                continue
            if response_code == 1:
                logger.info(
                    f"vt2 polling result retrievd correctly for job_id #{self.job_id}"
                )
                return result

        logger.info(
            f"max VT polls tried without getting any result. job_id #{self.job_id}"
        )
        return None

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch(
                    "requests.get",
                    return_value=MockResponse(
                        {"data": {"attributes": {"status": "completed"}}}, 200
                    ),
                ),
                patch(
                    "requests.post",
                    return_value=MockResponse(
                        {"scan_id": "scan_id_test", "data": {"id": "id_test"}}, 200
                    ),
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)
