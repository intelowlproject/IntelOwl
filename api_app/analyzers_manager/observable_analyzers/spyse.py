# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import requests
import re
from api_app.exceptions import AnalyzerRunException
from api_app.analyzers_manager import classes

from tests.mock_utils import if_mock_connections, patch, MockResponse


class Spyse(classes.ObservableAnalyzer):
    base_url: str = "https://api.spyse.com/v4/data/"

    def set_params(self, params):
        self.__api_key = self._secrets["api_key_name"]

    def run(self):
        params = {"key": self.__api_key}
        if self.observable_classification == self.ObservableTypes.DOMAIN:
            uri = f"domain/{self.observable_name}"
        elif self.observable_classification == self.ObservableTypes.IP:
            uri = f"ip/{self.observable_name}"
        elif self.observable_classification == self.ObservableTypes.GENERIC:
            if re.match(r"^[\w\.\+\-]+\@[\w]+\.[a-z]{2,3}$", self.observable_name):
                uri = f"email/{self.observable_name}"
            else:
                raise AnalyzerRunException(
                    f"{self.observable_name} not supported."
                    "Please enter a valid email address."
                )

        try:
            response = requests.get(self.base_url + uri, params=params)
            response.raise_for_status()
        except requests.RequestException as e:
            raise AnalyzerRunException(e)

        result = response.json()
        return result

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch(
                    "requests.get",
                    return_value=MockResponse({}, 200),
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)
