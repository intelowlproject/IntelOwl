# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import requests

from api_app.analyzers_manager import classes


class Auth0(classes.ObservableAnalyzer):
    name: str = "Auth0"
    url: str = "https://signals.api.auth0.com/v2.0/ip"

    _api_key_name: str

    @classmethod
    def update(cls) -> bool:
        pass

    def run(self):
        headers = {"X-Auth-Token": self._api_key_name}
        url = f"{self.url}/{self.observable_name}"
        response = requests.get(url, headers=headers)
        response.raise_for_status()

        json_response = response.json()
        return json_response
