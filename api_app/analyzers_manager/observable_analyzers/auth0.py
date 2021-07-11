# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import requests

from api_app.analyzers_manager import classes


class Auth0(classes.ObservableAnalyzer):
    name: str = "Auth0"
    base_url: str = "https://signals.api.auth0.com/v2.0/ip"

    def set_params(self, params):
        self.__api_key = self._secrets["api_key_name"]

    def run(self):
        headers = {"X-Auth-Token": self.__api_key}
        url = f"{self.base_url}/{self.observable_name}"
        response = requests.get(url, headers=headers)
        response.raise_for_status()

        json_response = response.json()
        return json_response
