# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging

import requests

from api_app.analyzers_manager.classes import BaseAnalyzerMixin
from api_app.exceptions import AnalyzerConfigurationException, AnalyzerRunException

logger = logging.getLogger(__name__)


class TriageMixin(BaseAnalyzerMixin):
    # using public endpoint as the default url
    base_url: str = "https://api.tria.ge/v0/"
    private_url: str = "https://private.tria.ge/api/v0/"
    report_url: str = "https://tria.ge/"

    def set_params(self, params):
        self.endpoint = params.get("endpoint", "public")
        if self.endpoint == "private":
            self.base_url = self.private_url

        self.__api_key = self._secrets["api_key_name"]
        self.report_type = params.get("report_type", "overview")
        if self.report_type not in ["overview", "complete"]:
            raise AnalyzerConfigurationException(
                "report_type must be 'overview' or 'complete' "
                f"but it is '{self.report_type}'"
            )
        self.max_tries = params.get("max_tries", 200)
        self.poll_distance = 3

        self.analysis_type = params.get("analysis_type", "search")

        self.final_report = {}

    def run(self):
        # this should be implemented by the extended classes
        pass

    @property
    def session(self):
        if not hasattr(self, "_session"):
            session = requests.Session()
            session.headers = {"Authorization": f"Bearer {self.__api_key}"}
            self._session = session
        return self._session

    def manage_submission_response(self, response):
        if response.status_code != 200:
            raise AnalyzerRunException("max retry attempts exceeded")

        sample_id = response.json().get("id", None)
        if sample_id is None:
            raise AnalyzerRunException("error sending sample")

        self.session.get(self.base_url + f"samples/{sample_id}/events")

        self.final_report["overview"] = self.get_overview_report(sample_id)

        if self.report_type == "complete":
            self.final_report["static_report"] = self.get_static_report(sample_id)

            self.final_report["task_report"] = {}
            for task in self.final_report["overview"]["tasks"].keys():
                status_code, task_report_json = self.get_task_report(sample_id, task)
                if status_code == 200:
                    self.final_report["task_report"][f"{task}"] = task_report_json

        analysis_id = self.final_report["overview"].get("sample", {}).get("id", "")
        if analysis_id:
            self.final_report["permalink"] = f"{self.report_url}{analysis_id}"

    def get_overview_report(self, sample_id):
        overview = self.session.get(
            self.base_url + f"samples/{sample_id}/overview.json"
        )
        return overview.json()

    def get_static_report(self, sample_id):
        static = self.session.get(self.base_url + f"samples/{sample_id}/reports/static")
        return static.json()

    def get_task_report(self, sample_id, task):
        task_report = self.session.get(
            self.base_url + f"samples/{sample_id}/{task}/report_triage.json"
        )
        return task_report.status_code, task_report.json()
