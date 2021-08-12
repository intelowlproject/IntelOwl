# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.conf import settings

import requests

from tests.mock_utils import MockResponse, patch, if_mock_connections
from api_app.connectors_manager import classes
from api_app.exceptions import ConnectorRunException


class YETI(classes.Connector):
    def set_params(self, params):
        self.verify_ssl: bool = params.get("verify_ssl", True)
        self.__url_name: str = self._secrets["url_key_name"]
        self.__api_key: str = self._secrets["api_key_name"]

    def run(self):
        # get observable value and type
        if self._job.is_sample:
            obs_value = self._job.md5
            obs_type = "file"
        else:
            obs_value = self._job.observable_name
            obs_type = self._job.observable_classification

        # create context
        context = {
            "source": "IntelOwl",
            "report": f"{settings.WEB_CLIENT_URL}/pages/scan/result/{self.job_id}",
            "status": "analyzed",
            "date": str(self._job.finished_analysis_time),
            "description": "IntelOwl's analysis report for Job: "
            f"{self.job_id} | {obs_value} | {obs_type}",
            "analyzers executed": ", ".join(self._job.analyzers_to_execute),
        }

        # get job tags
        tags = list(self._job.tags.all().values_list("label", flat=True))

        # request payload
        payload = {
            "value": obs_value,
            "source": "IntelOwl",
            "tags": tags,
            "context": context,
        }
        headers = {"Accept": "application/json", "X-Api-Key": self.__api_key}
        if self.__url_name.endswith("/"):
            self.__url_name = self.__url_name[:-1]
        url = f"{self.__url_name}/observable/"

        # create observable with `obs_value` if it doesn't exists
        # new context, tags, source are appended with existing ones
        try:
            resp = requests.post(
                url=url,
                headers=headers,
                json=payload,
                verify=self.verify_ssl,
            )
            resp.raise_for_status()
        except requests.RequestException as e:
            raise ConnectorRunException(e)

        return resp.json()

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch(
                    "requests.post",
                    return_value=MockResponse({}, 200),
                )
            )
        ]
        return super()._monkeypatch(patches=patches)
