# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import requests

from api_app.analyzers_manager import classes


class HaveIBeenPwned(classes.ObservableAnalyzer):
    url: str = "https://haveibeenpwned.com/api/v3/breachedaccount/"

    truncate_response: bool
    include_unverified: bool
    domain: str
    _api_key_name: str

    @classmethod
    def update(cls) -> bool:
        pass

    def run(self):
        params = {
            "truncateResponse": self.truncate_response,
            "includeUnverified": self.include_unverified,
        }
        if self.domain:
            params["domain"] = self.domain

        headers = {"hibp-api-key": self._api_key_name}

        response = requests.get(self.url + self.observable_name, params=params, headers=headers)
        response.raise_for_status()

        result = response.json()
        return result
