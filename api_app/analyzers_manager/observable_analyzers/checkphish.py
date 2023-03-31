# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import time

import requests

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from tests.mock_utils import MockUpResponse, if_mock_connections, patch


class CheckPhish(classes.ObservableAnalyzer):
    base_url: str = "https://developers.checkphish.ai/api/neo/scan"
    status_url: str = base_url + "/status"

    polling_tries: int
    polling_time: float

    _api_key_name: str

    def run(self):
        try:
            json_data = {
                "apiKey": self._api_key_name,
                "urlInfo": {"url": self.observable_name},
            }

            response = requests.post(CheckPhish.base_url, json=json_data)
            response.raise_for_status()
        except requests.RequestException as e:
            raise AnalyzerRunException(e)

        job_id = response.json().get("jobID")
        if job_id is None:
            raise AnalyzerRunException(
                "Job creation confirmation not received from CheckPhish."
            )

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
            try:
                response = requests.post(CheckPhish.status_url, json=json_data)
                response.raise_for_status()
            except requests.RequestException as e:
                raise AnalyzerRunException(e)

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

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch(
                    "requests.post",
                    side_effect=[
                        MockUpResponse({"jobID": "sample job ID"}, 200),
                        MockUpResponse({"status": "DONE"}, 200),
                    ],
                ),
            ),
        ]
        return super()._monkeypatch(patches=patches)
