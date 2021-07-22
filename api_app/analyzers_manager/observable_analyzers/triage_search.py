# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import time
import logging
import requests

from api_app.exceptions import AnalyzerRunException, AnalyzerConfigurationException
from api_app.analyzers_manager import classes

from tests.mock_utils import if_mock_connections, patch, MockResponse

logger = logging.getLogger(__name__)


class TriageSearch(classes.ObservableAnalyzer):
    # using public endpoint as the default url
    base_url: str = "https://api.tria.ge/v0/"
    private_url: str = "https://private.tria.ge/api/v0/"

    def set_params(self, params):
        self.endpoint = params.get("endpoint", "public")
        if self.endpoint == "private":
            self.base_url = self.private_url

        self.__api_key = self._secrets["api_key_name"]
        self.analysis_type = params.get("analysis_type", "search")
        self.report_type = params.get("report_type", "overview")
        self.max_tries = params.get("max_tries", 200)
        self.poll_distance = 5

    def run(self):
        self.session = requests.Session()
        self.session.headers = {"Authorization": f"Bearer {self.__api_key}"}

        response = None
        if self.analysis_type == "search":
            response = self.__triage_search()
        elif self.analysis_type == "submit":
            response = self.__triage_submit()
        else:
            raise AnalyzerConfigurationException(
                f"analysis type '{self.analysis_type}' not supported."
                "Supported are: 'search', 'submit'."
            )

        return response

    def __triage_search(self):
        if self.observable_classification == self.ObservableTypes.HASH.value:
            params = {"query": self.observable_name}
        else:
            params = {
                "query": f"{self.observable_classification}:{self.observable_name}"
            }

        response = self.session.get(self.base_url + "search", params=params)

        return response.json()

    def __triage_submit(self):
        final_report = {}
        data = {"kind": "url", "url": f"{self.observable_name}"}

        logger.info(f"triage {self.observable_name} sending sample for analysis")
        for _try in range(self.max_tries):
            logger.info(
                f"triage {self.observable_name} polling for result try #{_try + 1}"
            )
            response = self.session.post(self.base_url + "samples", json=data)
            if response.status_code == 200:
                break
            time.sleep(self.poll_distance)

        if response.status_code != 200:
            raise AnalyzerRunException("max retry attempts exceeded")

        sample_id = response.json().get("id", None)
        if sample_id is None:
            raise AnalyzerRunException("error sending sample")

        self.session.get(self.base_url + f"samples/{sample_id}/events")

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
        return (task_report.status_code, task_report.json())

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch(
                    "requests.Session.get",
                    return_value=MockResponse(
                        {"tasks": {"task_1": {}, "task_2": {}}, "data": []}, 200
                    ),
                ),
                patch(
                    "requests.Session.post",
                    return_value=MockResponse(
                        {"id": "sample_id", "status": "pending"}, 200
                    ),
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)
