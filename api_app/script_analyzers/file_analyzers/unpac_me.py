import requests
import logging
from api_app.script_analyzers.classes import FileAnalyzer
from api_app.exceptions import AnalyzerRunException
import time
from intel_owl import secrets
from typing import Dict

logger = logging.getLogger(__name__)


class UnpacMe(FileAnalyzer):
    base_url: str = "https://api.unpac.me/api/v1/"

    def set_config(self, additional_config_params):
        self.api_key_name = additional_config_params.get(
            "api_key_name", "UNPAC_ME_API_KEY"
        )
        private = additional_config_params.get("private", False)
        self.private = "private" if private else "public"
        self.__api_key = secrets.get_secret(self.api_key_name)
        # max no. of tries when polling for result
        self.max_tries = additional_config_params.get("max_tries", 30)
        # interval b/w HTTP requests when polling
        self.poll_distance = 5

    def run(self):
        if not self.__api_key:
            raise AnalyzerRunException(
                f"No API key retrieved with name: {self.api_key_name}"
            )
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
        return response.json()
