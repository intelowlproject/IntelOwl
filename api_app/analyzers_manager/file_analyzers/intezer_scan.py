# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import os
import time
import requests
import logging

from api_app.exceptions import AnalyzerRunException
from api_app.analyzers_manager.classes import FileAnalyzer
from api_app.helpers import get_now_date_only, get_binary

logger = logging.getLogger(__name__)


class IntezerScan(FileAnalyzer):
    base_url: str = "https://analyze.intezer.com/api/v2-0"

    def set_params(self, params):
        self.__api_key = self._secrets["api_key_name"]
        # max no. of tries when polling for result
        self.max_tries = params.get("max_tries", 200)
        # interval b/w HTTP requests when polling
        self.poll_distance = 3
        self.is_test = params.get("is_test", False)

    def run(self):
        intezer_token = os.environ.get("INTEZER_TOKEN", "")
        intezer_token_date = os.environ.get("INTEZER_TOKEN_DATE", None)
        today = get_now_date_only()
        if not intezer_token or intezer_token_date != today:
            intezer_token = _get_access_token(self.__api_key)
            if not intezer_token:
                raise AnalyzerRunException("token extraction failed")

        return self.__intezer_scan_file(intezer_token)

    def __intezer_scan_file(self, intezer_token):
        session = requests.session()
        session.headers["Authorization"] = f"Bearer {intezer_token}"

        name_to_send = self.filename if self.filename else self.md5
        binary = get_binary(self.job_id)
        files = {"file": (name_to_send, binary)}
        logger.info(f"intezer md5 {self.md5} sending sample for analysis")
        response = session.post(self.base_url + "/analyze", files=files)
        if response.status_code != 201:
            raise AnalyzerRunException(
                f"failed analyze request, status code {response.status_code}"
            )

        for chance in range(self.max_tries):
            if response.status_code != 200:
                time.sleep(self.poll_distance)
                logger.info(
                    f"intezer md5 {self.md5} polling for result try #{chance + 1}"
                )
                result_url = response.json().get("result_url", "")
                response = session.get(self.base_url + result_url)
                response.raise_for_status()

        if response.status_code != 200 and not self.is_test:
            raise AnalyzerRunException("received max tries attempts")

        return response.json()


def _get_access_token(api_key):
    """
    this should be done just once in a day
    """
    base_url = "https://analyze.intezer.com/api/v2-0"
    response = requests.post(
        base_url + "/get-access-token", json={"api_key": api_key}
    )  # lgtm [py/uninitialized-local-variable]
    response.raise_for_status()
    response_json = response.json()
    token = response_json.get("result", "")
    os.environ["INTEZER_TOKEN"] = token
    os.environ["INTEZER_TOKEN_DATE"] = get_now_date_only()
    return token
