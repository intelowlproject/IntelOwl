# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import time

import requests

from api_app.analyzers_manager import classes
from api_app.exceptions import AnalyzerRunException
from tests.mock_utils import MockResponse, if_mock_connections, patch


class CheckPhish(classes.ObservableAnalyzer):
    base_url: str = "https://developers.checkphish.ai/api/neo/scan"
    status_url: str = base_url + "/status"

    def set_params(self, _params):
        self.__api_key = self._secrets["api_key_name"]

    def run(self):
        try:
            json_data = {
                "apiKey": self.__api_key,
                "urlInfo": {"url": self.observable_name},
            }

            response = requests.post(CheckPhish.base_url, json=json_data)
            response.raise_for_status()
        except requests.RequestException as e:
            raise AnalyzerRunException(e)

        result = response.json()

        return self.retrieve_analysis_status(result["jobID"])

    def retrieve_analysis_status(self, job_id):
        try:
            json_data = {
                "apiKey": self.__api_key,
                "jobID": job_id,
                "insights": True,  # setting "insights" to True adds "screenshot_path"
                # and "resolved" fields to the response
            }

            response = requests.post(CheckPhish.status_url, json=json_data)
            response.raise_for_status()
        except requests.RequestException as e:
            raise AnalyzerRunException(e)

        result = response.json()
        if result["status"] != "DONE":
            time.sleep(0.5)
            return self.retrieve_analysis_status(job_id)

        return result

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch(
                    "requests.post",
                    return_value=MockResponse({"jobID": "sample job ID"}, 200),
                    url=cls.base_url,
                ),
            ),
            if_mock_connections(
                patch(
                    "requests.post",
                    return_value=MockResponse({"status": "DONE"}, 200),
                    url=cls.status_url,
                ),
            ),
        ]
        return super()._monkeypatch(patches=patches)
