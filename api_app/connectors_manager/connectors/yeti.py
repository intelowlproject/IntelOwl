# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.conf import settings

import pyeti

from tests.mock_utils import patch, if_mock_connections
from api_app.connectors_manager import classes
from api_app.exceptions import ConnectorRunException


class YETI(classes.Connector):
    def set_params(self, params):
        self.verify_ssl = params.get("verify_ssl", True)
        self.__url_name = self._secrets["url_key_name"]
        self.__api_key = self._secrets["api_key_name"]

    def run(self):
        # set up client
        self.yeti_instance = pyeti.YetiApi(
            url=self.__url_name, api_key=self.__api_key, verify_ssl=self.verify_ssl
        )

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

        # create observable with `obs_value` if it doesn't exists
        # new context, tags, source are appended with existing ones
        result = self.yeti_instance.observable_add(
            value=obs_value, tags=tags, context=context, source="IntelOwl"
        )

        if result is None:
            raise ConnectorRunException(
                "Error while creating observable"
                f"Possible Error: Couldn't guess observable type for {obs_value}"
            )

        return result

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch(
                    "pyeti.YetiApi",
                    side_effect=MockYetiApi,
                )
            )
        ]
        return super()._monkeypatch(patches=patches)


class MockYetiApi:
    """
    Mock Pyeti instance for testing
    """

    def __init__(self, *args, **kwargs) -> None:
        pass

    def observable_add(self, value, tags, context, *args, **kwargs):
        return {
            "value": value,
            "tags": tags,
            "context": context,
        }
