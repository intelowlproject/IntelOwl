# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import requests

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from tests.mock_utils import MockUpResponse, if_mock_connections, patch


class URLHaus(classes.ObservableAnalyzer):
    url = "https://urlhaus-api.abuse.ch/v1/"
    disable: bool = False  # optional

    def update(self) -> bool:
        pass

    def run(self):
        if self.disable:
            return {"disabled": True}

        headers = {"Accept": "application/json"}
        if self.observable_classification in [
            self.ObservableTypes.DOMAIN,
            self.ObservableTypes.IP,
        ]:
            uri = "host/"
            post_data = {"host": self.observable_name}
        elif self.observable_classification == self.ObservableTypes.URL:
            uri = "url/"
            post_data = {"url": self.observable_name}
        else:
            raise AnalyzerRunException(
                f"not supported observable type {self.observable_classification}."
            )

        response = requests.post(self.url + uri, data=post_data, headers=headers)
        response.raise_for_status()

        return response.json()

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch(
                    "requests.post",
                    return_value=MockUpResponse({}, 200),
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)
