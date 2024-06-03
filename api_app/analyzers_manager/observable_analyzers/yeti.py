# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import requests

from api_app.analyzers_manager import classes
from tests.mock_utils import MockUpResponse, if_mock_connections, patch


class YETI(classes.ObservableAnalyzer):
    verify_ssl: bool
    results_count: int
    regex: False
    _url_key_name: str
    _api_key_name: str

    def run(self):
        # request payload
        payload = {
            "filter": {"value": self._job.observable_name},
            "params": {"regex": self.regex, "range": self.results_count},
        }
        headers = {"Accept": "application/json", "X-Api-Key": self._api_key_name}
        if self._url_key_name and self._url_key_name.endswith("/"):
            self._url_key_name = self._url_key_name[:-1]
        url = f"{self._url_key_name}/api/v2/observablesearch/"

        # search for observables
        resp = requests.post(
            url=url,
            headers=headers,
            json=payload,
            verify=self.verify_ssl,
        )
        resp.raise_for_status()

        return resp.json()

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch(
                    "requests.post",
                    return_value=MockUpResponse([], 200),
                )
            )
        ]
        return super()._monkeypatch(patches=patches)
