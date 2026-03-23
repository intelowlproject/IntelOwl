# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import requests

from api_app.analyzers_manager import classes


class YETI(classes.ObservableAnalyzer):
    verify_ssl: bool
    results_count: int
    regex: False
    _url_key_name: str
    _api_key_name: str

    def run(self):
        # request payload
        payload = {
            "query": {"value": self._job.analyzable.name},
            "count": self.results_count,
        }
        headers = {"Accept": "application/json", "X-Api-Key": self._api_key_name}
        if self._url_key_name and self._url_key_name.endswith("/"):
            self._url_key_name = self._url_key_name[:-1]
        url = f"{self._url_key_name}/api/v2/observables/search/"

        # search for observables
        resp = requests.post(
            url=url,
            headers=headers,
            json=payload,
            verify=self.verify_ssl,
        )
        resp.raise_for_status()

        return resp.json()
