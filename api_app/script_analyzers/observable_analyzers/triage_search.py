import time
import logging
import requests

from api_app.exceptions import AnalyzerRunException, AnalyzerConfigurationException
from api_app.script_analyzers import classes
from intel_owl import secrets


logger = logging.getLogger(__name__)


class TriageSearch(classes.ObservableAnalyzer):
    # using public endpoint as the default url
    base_url: str = "https://api.tria.ge/v0/"
    private_url: str = "https://private.tria.ge/api/v0/"

    def set_config(self, additional_config_params):
        self.endpoint = additional_config_params.get("endpoint", "public")
        if self.endpoint == "private":
            self.base_url = self.private_url

        self.api_key_name = additional_config_params.get("api_key_name", "TRIAGE_KEY")
        self.__api_key = secrets.get_secret(self.api_key_name)
        self.analysis_type = additional_config_params.get("analysis_type", "search")
        self.report_type = additional_config_params.get("report_type", "overview")
        self.max_tries = additional_config_params.get("max_tries", 200)
        self.poll_distance = 5

    def run(self):
        if not self.__api_key:
            raise AnalyzerRunException(
                f"No API key retrieved with name: {self.api_key_name}"
            )

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
        if self.observable_classification == "hash":
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
