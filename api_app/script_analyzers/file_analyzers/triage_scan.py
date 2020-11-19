import time
import logging
import requests

from api_app.exceptions import AnalyzerRunException
from api_app.helpers import get_binary
from api_app.script_analyzers import classes
from intel_owl import secrets


logger = logging.getLogger(__name__)


class TriageScanFile(classes.FileAnalyzer):
    # using public endpoint as the default url
    base_url: str = "https://api.tria.ge/v0/"
    private_url: str = "https://private.tria.ge/api/v0/"

    def set_config(self, additional_config_params):
        self.endpoint = additional_config_params.get("endpoint", "public")
        if self.endpoint == "private":
            self.base_url = self.private_url

        self.api_key_name = additional_config_params.get("api_key_name", "TRIAGE_KEY")
        self.__api_key = secrets.get_secret(self.api_key_name)
        self.report_type = additional_config_params.get("report_type", "overview")
        self.max_tries = additional_config_params.get("max_tries", 200)
        self.poll_distance = 3

    def run(self):
        final_report = {}
        if not self.__api_key:
            raise AnalyzerRunException(
                f"No API key retrieved with name: {self.api_key_name}"
            )

        self.headers = {"Authorization": f"Bearer {self.__api_key}"}

        name_to_send = self.filename if self.filename else self.md5
        binary = get_binary(self.job_id)
        files = {
            "file": (name_to_send, binary),
            "_json": (None, b'{"kind": "file", "interactive": false}'),
        }

        logger.info(f"triage md5 {self.md5} sending sample for analysis")
        for _try in range(self.max_tries):
            logger.info(f"triage md5 {self.md5} polling for result try #{_try + 1}")
            response = requests.post(
                self.base_url + "samples", headers=self.headers, files=files
            )
            if response.status_code == 200:
                break
            time.sleep(self.poll_distance)

        if response.status_code != 200:
            raise AnalyzerRunException("max retry attempts exceeded")

        sample_id = response.json().get("id", None)
        if sample_id is None:
            raise AnalyzerRunException("error sending sample")

        requests.get(
            self.base_url + f"samples/{sample_id}/events", headers=self.headers
        )

        if self.report_type == "overview" or self.report_type == "complete":
            final_report["overview"] = self.get_overview_report(sample_id)

        if self.report_type == "complete":
            final_report["static_report"] = self.get_static_report(sample_id)

            final_report["task_report"] = {}
            for task in final_report["overview"]["tasks"].keys():
                status_code, task_report_json = self.get_task_report(sample_id, task)
                if status_code == 200:
                    final_report["task_report"][f"{task}"] = task_report_json

        return final_report

    def get_overview_report(self, sample_id):
        overview = requests.get(
            self.base_url + f"samples/{sample_id}/overview.json",
            headers=self.headers,
        )
        return overview.json()

    def get_static_report(self, sample_id):
        static = requests.get(
            self.base_url + f"samples/{sample_id}/reports/static",
            headers=self.headers,
        )
        return static.json()

    def get_task_report(self, sample_id, task):
        task_report = requests.get(
            self.base_url + f"samples/{sample_id}/{task}/report_triage.json",
            headers=self.headers,
        )
        return (task_report.status_code, task_report.json())
