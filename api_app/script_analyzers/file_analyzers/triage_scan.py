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
        self.max_tries = additional_config_params.get("max_tries", 200)
        self.poll_distance = 3

    def run(self):
        final_report = {}
        if not self.__api_key:
            raise AnalyzerRunException(
                f"No API key retrieved with name: {self.api_key_name}"
            )

        headers = {"Authorization": f"Bearer {self.__api_key}"}

        name_to_send = self.filename if self.filename else self.md5
        binary = get_binary(self.job_id)
        files = {
            "file": (name_to_send, binary),
            "_json": (None, b'{"kind": "file", "interactive": false}'),
        }

        logger.info(f"triage md5 {self.md5} sending sample for analysis")
        response = requests.post(
            self.base_url + "samples", headers=headers, files=files
        )

        _try = 0
        while _try < self.max_tries and response.status_code != 200:
            time.sleep(self.poll_distance)
            logger.info(f"triage md5 {self.md5} polling for result try #{_try + 1}")
            response = requests.post(
                self.base_url + "samples", headers=headers, files=files
            )
            response.raise_for_status()
            _try += 1

        if response.status_code != 200:
            raise AnalyzerRunException("max retry attempts exceeded")

        sample_id = response.json().get("id", None)
        if sample_id is None:
            raise AnalyzerRunException("error sending sample")

        # Event stream is opened. Updates till the task is completed
        requests.get(self.base_url + f"samples/{sample_id}/events", headers=headers)

        # Get overview report
        overview = requests.get(
            self.base_url + f"samples/{sample_id}/overview.json",
            headers=headers,
        )
        overview_json = overview.json()
        final_report["overview"] = overview_json

        # Get static report
        static_report = requests.get(
            self.base_url + f"samples/{sample_id}/reports/static",
            headers=headers,
        )
        static_report_json = static_report.json()
        final_report["static_report"] = static_report_json

        # Get task-wise detailed report
        final_report["task_report"] = {}
        for task in final_report["overview"]["tasks"].keys():
            task_report = requests.get(
                self.base_url + f"samples/{sample_id}/{task}/report_triage.json",
                headers=headers,
            )
            if task_report.status_code == 200:
                task_report_json = task_report.json()
                final_report["task_report"][f"{task}"] = task_report_json

        return final_report
