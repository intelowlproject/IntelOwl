# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import requests
import logging
from api_app.analyzers_manager.classes import FileAnalyzer
from api_app.exceptions import AnalyzerRunException
import time
from typing import Dict

from tests.mock_utils import patch, if_mock, MockResponse

logger = logging.getLogger(__name__)


def mocked_unpacme_post(*args, **kwargs):
    return MockResponse({"id": "test"}, 200)


def mocked_unpacme_get(*args, **kwargs):
    return MockResponse({"id": "test", "status": "complete"}, 200)


@if_mock(
    [
        patch(
            "requests.get",
            side_effect=mocked_unpacme_get,
        ),
        patch(
            "requests.post",
            side_effect=mocked_unpacme_post,
        ),
    ]
)
class UnpacMe(FileAnalyzer):
    base_url: str = "https://api.unpac.me/api/v1/"

    def set_params(self, params):
        private = params.get("private", False)
        self.private = "private" if private else "public"
        self.__api_key = self._secrets["api_key_name"]
        # max no. of tries when polling for result
        self.max_tries = params.get("max_tries", 30)
        # interval b/w HTTP requests when polling
        self.poll_distance = 5

    def run(self):
        self.headers = {"Authorization": "Key %s" % self.__api_key}
        unpac_id = self._upload()
        logger.info(f"md5 {self.md5} job {self.job_id} uploaded id {unpac_id}")
        for chance in range(self.max_tries):
            time.sleep(self.poll_distance)
            logger.info(
                f"unpacme polling, try n.{chance + 1}."
                f" job_id {self.job_id}. starting the query"
            )
            status = self._get_status(unpac_id)
            if status == "fail":
                logger.error(f"md5 {self.md5} job {self.job_id} analysis has failed")
                raise AnalyzerRunException("failed analysis")
            if status != "complete":
                logger.info(
                    f"md5 {self.md5} job {self.job_id} id {unpac_id} status {status}"
                )
                continue
            return self._get_report(unpac_id)

    def _req_with_checks(self, url, files=None, post=False):
        try:
            if post:
                r = requests.post(
                    self.base_url + url, files=files, headers=self.headers
                )
            else:
                headers = self.headers if self.private == "private" else {}
                r = requests.get(self.base_url + url, files=files, headers=headers)
            r.raise_for_status()
        except requests.exceptions.HTTPError as e:
            logger.error(
                f"md5 {self.md5} job {self.job_id} url {url} has http error {str(e)}"
            )
            if post:
                raise AnalyzerRunException("Monthly quota exceeded!")
            raise AnalyzerRunException(e)
        except requests.exceptions.Timeout as e:
            logger.error(
                f"md5 {self.md5} job {self.job_id} url {url} has timeout error {str(e)}"
            )
            raise AnalyzerRunException(e)
        except requests.exceptions.RequestException as e:
            logger.error(
                f"md5 {self.md5} job {self.job_id} url {url} failed with error {str(e)}"
            )
            raise AnalyzerRunException(e)
        return r

    def _upload(self) -> str:
        with open(self.filepath, "rb") as f:
            file_data = f.read()
        files = {"file": (self.filename, file_data)}
        r = self._req_with_checks("private/upload", files=files, post=True)
        response = r.json()
        if "id" not in response:
            raise AnalyzerRunException(
                f"md5 {self.md5} job {self.job_id} function upload id not in response"
            )
        return response["id"]

    def _get_status(self, unpac_me_id) -> str:
        response = self._req_with_checks(f"{self.private}/status/{unpac_me_id}")
        return response.json().get("status", False)

    def _get_report(self, unpac_me_id) -> Dict:
        response = self._req_with_checks(f"{self.private}/results/{unpac_me_id}")
        result = response.json()
        analysis_id = result.get("id", "")
        if analysis_id:
            result["permalink"] = f"https://www.unpac.me/results/{analysis_id}"
        return result
