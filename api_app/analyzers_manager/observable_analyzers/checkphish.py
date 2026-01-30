# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import time

import requests

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import AnalyzerRunException


class CheckPhish(classes.ObservableAnalyzer):
    url: str = "https://developers.checkphish.ai/api/neo/scan"
    status_url: str = url + "/status"

    polling_tries: int
    polling_time: float

    _api_key_name: str

    @classmethod
    def update(cls) -> bool:
        pass

    def run(self):
        json_data = {
            "apiKey": self._api_key_name,
            "urlInfo": {"url": self.observable_name},
        }

        response = requests.post(CheckPhish.url, json=json_data)
        response.raise_for_status()

        job_id = response.json().get("jobID")
        if job_id is None:
            raise AnalyzerRunException("Job creation confirmation not received from CheckPhish.")

        return self.__poll_analysis_status(job_id)

    def __poll_analysis_status(self, job_id):
        json_data = {
            "apiKey": self._api_key_name,
            "jobID": job_id,  # Assumption: jobID corresponds to an actual job.
            # This is always the case when this function is called
            # in the "run" function.
            "insights": True,  # setting "insights" to True adds "screenshot_path"
            # and "resolved" fields to the response
        }
        for chance in range(self.polling_tries):
            if chance != 0:
                time.sleep(self.polling_time)
            response = requests.post(CheckPhish.status_url, json=json_data)
            response.raise_for_status()
            result = response.json()
            status_json = result.get("status", "")
            error = result.get("error", False)
            if status_json is None:
                raise AnalyzerRunException(f"Job {job_id} not found.")
            if error:
                raise AnalyzerRunException(f"Analysis error for job_id {job_id}")
            if status_json == "DONE":
                return result
        raise AnalyzerRunException(f'Job "{job_id}" status retrieval failed.')
