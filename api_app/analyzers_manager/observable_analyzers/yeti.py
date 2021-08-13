# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import pyeti

from tests.mock_utils import patch, if_mock_connections
from api_app.analyzers_manager import classes


class YETI(classes.ObservableAnalyzer):
    def set_params(self, params):
        self.verify_ssl = params.get("verify_ssl", True)
        self.results_count = params.get("results_count", 50)
        self.__url_name = self._secrets["url_key_name"]
        self.__api_key = self._secrets["api_key_name"]

    def run(self):
        # set up client
        yeti_instance = pyeti.YetiApi(
            url=self.__url_name, api_key=self.__api_key, verify_ssl=self.verify_ssl
        )

        # search for observables
        results = yeti_instance.observable_search(
            value=self._job.observable_name, count=self.results_count
        )

        return results

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

    def observable_search(self, *args, **kwargs):
        return []
