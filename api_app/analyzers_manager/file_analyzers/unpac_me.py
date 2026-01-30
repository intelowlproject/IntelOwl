# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging
import time
from typing import Dict

import requests

from api_app.analyzers_manager.classes import FileAnalyzer
from api_app.analyzers_manager.exceptions import AnalyzerRunException

logger = logging.getLogger(__name__)


class UnpacMe(FileAnalyzer):
    url: str = "https://api.unpac.me/api/v1/"

    _api_key_name: str
    private: bool
    # max no. of tries when polling for result
    max_tries: int

    def config(self, runtime_configuration: Dict):
        super().config(runtime_configuration)
        self.private: str = "private" if self.private else "public"

        self.headers = {"Authorization": f"Key {self._api_key_name}"}

        # interval b/w HTTP requests when polling
        self.poll_distance = 5

    def run(self):
        report = {}
        unpac_id = self._upload()
        logger.info(f"md5 {self.md5} job {self.job_id} uploaded id {unpac_id}")
        for chance in range(self.max_tries):
            time.sleep(self.poll_distance)
            logger.info(f"unpacme polling, try n.{chance + 1}. job_id {self.job_id}. starting the query")
            status = self._get_status(unpac_id)
            logger.info(f"md5 {self.md5} job {self.job_id} id {unpac_id} status {status}")
            if status == "fail":
                raise AnalyzerRunException(f"failed analysis for {self.md5} job {self.job_id}")
            if status == "complete":
                report = self._get_report(unpac_id)
                break
            else:
                continue

        return report

    def _req_with_checks(self, url, files=None, post=False):
        try:
            if post:
                r = requests.post(self.url + url, files=files, headers=self.headers)
            else:
                headers = self.headers if self.private == "private" else {}
                r = requests.get(self.url + url, files=files, headers=headers)
            r.raise_for_status()
        except requests.exceptions.HTTPError as e:
            logger.error(f"md5 {self.md5} job {self.job_id} url {url} has http error {str(e)}")
            if post:
                raise AnalyzerRunException("Monthly quota exceeded!")
            raise AnalyzerRunException(e)
        except requests.exceptions.Timeout as e:
            logger.error(f"md5 {self.md5} job {self.job_id} url {url} has timeout error {str(e)}")
            raise AnalyzerRunException(e)
        except requests.exceptions.RequestException as e:
            logger.error(f"md5 {self.md5} job {self.job_id} url {url} failed with error {str(e)}")
            raise AnalyzerRunException(e)
        return r

    def _upload(self) -> str:
        with open(self.filepath, "rb") as f:
            file_data = f.read()
        files = {"file": (self.filename, file_data)}
        r = self._req_with_checks("private/upload", files=files, post=True)
        response = r.json()
        if "id" not in response:
            raise AnalyzerRunException(f"md5 {self.md5} job {self.job_id} function upload id not in response")
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
